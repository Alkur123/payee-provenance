"""Payee-provenance gate as an HTTP service a bank or PSP can run in front of its payment API. Standard library only.

    PP_BANK_KEY=<hex> PP_GATE_KEY=<hex> PP_RECEIPT_KEY=<hex> PP_APP_KEY=<hex> python -m payee_provenance.server --port 8080

Keys (each at least 32 bytes, hex-encoded) never leave the bank: BANK seals session state built from the bank's records,
APP signs the customer's answer to a confirmation in the bank's app, GATE mints execution tokens for the payment backend,
RECEIPT signs the receipt chain. The service refuses to start without all four, and refuses to start if the stored
receipt chain does not verify.

POST /v1/decide    {op, state, seal, target, amount, new_value?, agent_id, mandate_id, mandate_version, instruction}
                   -> verdict, class, source, reasons, receipt; plus an execution token (ALLOW) or a decision_id (CONFIRM)
POST /v1/confirm   {decision_id, approved, customer_sig}  customer_sig = HMAC(APP, "<decision_id>:<approved>")
                   -> approved: a token valid only after the hold; declined: no token. Both are receipted.
GET  /v1/receipts/head    -> {seq, mac}: store it outside the receipt store (anchor)
POST /v1/receipts/verify  {anchor?} -> {verified}
GET  /healthz
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .bank_api import OPS, UntrustedState, mint_token, open_session
from .gate import (ALLOW, BLOCK, STEP_UP, confirmation_card, decide_add_beneficiary, decide_collect, decide_credential,
                   decide_payment, decide_update_beneficiary, release_policy)
from .receipt import ReceiptChain

MAX_BODY = 256 * 1024


def _key(name: str) -> bytes:
    v = os.environ.get(name, "")
    try:
        k = bytes.fromhex(v)
    except ValueError:
        k = b""
    if len(k) < 32:
        raise SystemExit(f"{name} must be set to at least 32 bytes, hex-encoded; refusing to start")
    return k


class Gate:
    def __init__(self, bank_key, gate_key, receipt_key, app_key, receipts_path=None):
        self.bank_key, self.gate_key, self.app_key = bank_key, gate_key, app_key
        self.receipts_path = receipts_path
        if receipts_path and os.path.exists(receipts_path):
            self.chain = ReceiptChain.load(receipts_path, receipt_key)
            if not self.chain.verify():
                raise SystemExit("stored receipt chain does not verify; refusing to start")
        else:
            self.chain = ReceiptChain(receipt_key)
        self.pending: dict = {}
        self.lock = threading.Lock()                       # guards the chain and pending decisions
        self._cv = threading.Condition()                   # group commit: one fsync covers every receipt waiting
        self._durable = len(self.chain.entries)
        self._flushing = False

    def _wait_durable(self, seq: int) -> None:
        """Return only once receipt `seq` is on disk. Whichever waiting thread finds no flush in progress writes and
        fsyncs everything appended so far; the others wait for it. Durability per response is unchanged; the cost of
        one fsync is shared by all concurrent requests."""
        with self._cv:
            while self._durable <= seq:
                if self._flushing:
                    self._cv.wait()
                    continue
                self._flushing = True
                with self.lock:
                    upto = len(self.chain.entries)
                self._cv.release()
                try:
                    self.chain.save(self.receipts_path, upto=upto)
                finally:
                    self._cv.acquire()
                    self._flushing = False
                self._durable = max(self._durable, upto)
                self._cv.notify_all()

    def _receipt(self, req, d, verdict, confirmed=None):
        with self.lock:
            rec = self.chain.append(agent_id=str(req.get("agent_id", "")), mandate_id=str(req.get("mandate_id", "")),
                                    mandate_version=int(req.get("mandate_version", 0)),
                                    instruction=str(req.get("instruction", "")), payee=str(req.get("target", "")),
                                    amount=float(req.get("amount", 0)), payee_class=d.payee_class, source=d.source,
                                    verdict=verdict, confirmed_by_customer=confirmed)
        if self.receipts_path:
            self._wait_durable(rec["seq"])
        return {"seq": rec["seq"], "mac": rec["mac"]}

    def decide(self, req: dict) -> tuple:
        op = req.get("op")
        if op not in OPS:
            return 400, {"error": f"op must be one of {list(OPS)}"}
        try:
            s = open_session(base64.b64decode(req["state"]), str(req["seal"]), self.bank_key)
        except (KeyError, ValueError, UntrustedState) as e:
            return 403, {"error": "session state is not sealed by the bank", "detail": type(e).__name__}
        target, amount = str(req.get("target", "")), float(req.get("amount", 0))
        new_value = str(req.get("new_value", ""))
        d = {"pay": lambda: decide_payment(target, amount, s),
             "approve_collect": lambda: decide_collect(target, amount, s),
             "add_payee": lambda: decide_add_beneficiary(target, s),
             "update_payee": lambda: decide_update_beneficiary(target, new_value, s),
             "set_password": lambda: decide_credential(target, s)}[op]()
        out = {"verdict": d.verdict, "payee_class": d.payee_class, "source": d.source, "reasons": d.reasons,
               "receipt": self._receipt(req, d, d.verdict)}
        exec_target = new_value if op == "update_payee" else target
        if d.verdict == ALLOW:
            out["token"] = mint_token(self.gate_key, op, exec_target, amount)
        elif d.verdict == STEP_UP:
            did = secrets.token_hex(12)
            known = d.payee_class == "K"
            with self.lock:
                self.pending[did] = (req, d, op, exec_target, amount, not known)
            out["decision_id"] = did
            out["card"] = confirmation_card(d, exec_target, amount, str(req.get("lang", "en")))
        return 200, out

    def confirm(self, req: dict) -> tuple:
        did, approved = str(req.get("decision_id", "")), bool(req.get("approved"))
        want = hmac.new(self.app_key, f"{did}:{str(approved).lower()}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, str(req.get("customer_sig", ""))):
            return 403, {"error": "confirmation is not signed by the bank's app"}
        with self.lock:
            item = self.pending.pop(did, None)
        if item is None:
            return 404, {"error": "unknown or already answered decision"}
        oreq, d, op, exec_target, amount, is_new = item
        verdict, hold_h = release_policy(d, approved, payee_is_new=is_new)
        out = {"verdict": verdict, "hold_hours": hold_h, "receipt": self._receipt(oreq, d, STEP_UP, confirmed=approved)}
        if verdict != BLOCK:
            out["token"] = mint_token(self.gate_key, op, exec_target, amount, not_before=time.time() + hold_h * 3600)
        return 200, out


def make_handler(gate: Gate):
    class H(BaseHTTPRequestHandler):
        server_version = "payee-provenance/3.1"

        def log_message(self, *a):        # no request logging of bodies or identifiers by default
            pass

        def _send(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self):
            n = int(self.headers.get("Content-Length", "0"))
            if n > MAX_BODY:
                raise ValueError("body too large")
            return json.loads(self.rfile.read(n) or b"{}")

        def do_GET(self):
            if self.path == "/healthz":
                return self._send(200, {"ok": True, "receipts": len(gate.chain.entries)})
            if self.path == "/v1/receipts/head":
                with gate.lock:
                    return self._send(200, gate.chain.head())
            return self._send(404, {"error": "not found"})

        def do_POST(self):
            try:
                req = self._json()
            except (ValueError, json.JSONDecodeError):
                return self._send(400, {"error": "invalid JSON body"})
            if self.path == "/v1/decide":
                return self._send(*gate.decide(req))
            if self.path == "/v1/confirm":
                return self._send(*gate.confirm(req))
            if self.path == "/v1/receipts/verify":
                with gate.lock:
                    return self._send(200, {"verified": gate.chain.verify(anchor=req.get("anchor"))})
            return self._send(404, {"error": "not found"})
    return H


class _Server(ThreadingHTTPServer):
    request_queue_size = 256      # the default of 5 drops connections under concurrency (each retry costs ~0.5 s)
    daemon_threads = True


def serve(gate: Gate, host="127.0.0.1", port=8080) -> ThreadingHTTPServer:
    return _Server((host, port), make_handler(gate))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--receipts", default=os.environ.get("PP_RECEIPTS_PATH", "receipts.jsonl"))
    a = ap.parse_args()
    g = Gate(_key("PP_BANK_KEY"), _key("PP_GATE_KEY"), _key("PP_RECEIPT_KEY"), _key("PP_APP_KEY"), a.receipts)
    httpd = serve(g, a.host, a.port)
    print(f"payee-provenance gate listening on {a.host}:{a.port}, {len(g.chain.entries)} receipts verified", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
