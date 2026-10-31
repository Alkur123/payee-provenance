"""Reference integration: the trust boundary and complete mediation, made explicit (v3.1, after external review).

Two properties the decision functions in gate.py assume but cannot enforce on their own:

1. Trusted state. The Session that drives every decision must come from the bank, never from the agent. Here the bank
   seals the session state with its own key (seal_session); the production API accepts only state whose seal verifies,
   so an agent platform that fabricates customer messages or beneficiary records gets a refusal, not a decision.

2. Complete mediation. No route may move money or authority without passing through the gate. Here the payment backend
   executes an operation only with a single-use execution token that the gate mints for that exact operation, payee and
   amount, after an ALLOW (or a confirmed STEP_UP). Calling the backend directly, replaying a token, or presenting a token
   minted for a different payee or amount is refused.

This is a vendor-neutral stand-in for a bank's payment API, runnable without any external service.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import asdict
from typing import Dict, List, Optional, Tuple

from .gate import (ALLOW, STEP_UP, Beneficiary, Decision, Document, Session, canon, decide_add_beneficiary,
                   decide_collect, decide_credential, decide_payment, decide_update_beneficiary)

OPS = ("pay", "approve_collect", "add_payee", "update_payee", "set_password")


class UntrustedState(Exception):
    """The session state did not come from the bank (seal missing or invalid)."""


class Refused(Exception):
    """The backend refused an operation that did not carry a valid execution token."""


def _canonical_state(s: Session) -> bytes:
    d = {
        "principal_messages": s.principal_messages,
        "beneficiaries": {k: asdict(v) for k, v in sorted(s.beneficiaries.items())},
        "named_documents": {k: (asdict(v) if isinstance(v, Document) else {"text": str(v), "written_by_agent": False})
                            for k, v in sorted(s.named_documents.items())},
        "world_inputs": [list(x) for x in s.world_inputs],
        "mandate_cap": s.mandate_cap,
        "principal_amounts": s.principal_amounts,
        "biller_registry": dict(sorted(s.biller_registry.items())),
        "bill_fetch": dict(sorted(s.bill_fetch.items())),
    }
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")


def seal_session(s: Session, bank_key: bytes) -> Tuple[bytes, str]:
    """Run by the BANK when it builds the session from its own records. Returns (state, seal)."""
    blob = _canonical_state(s)
    return blob, hmac.new(bank_key, blob, hashlib.sha256).hexdigest()


def open_session(blob: bytes, seal: str, bank_key: bytes) -> Session:
    """Rebuild a Session only if the bank's seal verifies; otherwise raise UntrustedState."""
    if not hmac.compare_digest(hmac.new(bank_key, blob, hashlib.sha256).hexdigest(), str(seal)):
        raise UntrustedState("session state is not sealed by the bank")
    d = json.loads(blob.decode("utf-8"))
    return Session(
        principal_messages=list(d["principal_messages"]),
        beneficiaries={k: Beneficiary(**v) for k, v in d["beneficiaries"].items()},
        named_documents={k: Document(**v) for k, v in d["named_documents"].items()},
        world_inputs=[tuple(x) for x in d["world_inputs"]],
        mandate_cap=d["mandate_cap"],
        principal_amounts=list(d["principal_amounts"]),
        biller_registry=dict(d["biller_registry"]),
        bill_fetch=dict(d["bill_fetch"]),
    )


def _token_body(op: str, target: str, amount: float, nonce: str) -> bytes:
    return json.dumps([op, canon(target), round(float(amount), 2), nonce], separators=(",", ":")).encode("utf-8")


class PaymentBackend:
    """The bank's money-moving system. It knows nothing about provenance; it only refuses work without a gate token."""

    def __init__(self, gate_key: bytes):
        self._key = gate_key
        self._spent: set = set()
        self.executed: List[dict] = []

    def execute(self, op: str, target: str, amount: float = 0.0, token: Optional[dict] = None) -> dict:
        if op not in OPS:
            raise Refused(f"unknown operation {op!r}")
        if not token or "nonce" not in token or "tag" not in token:
            raise Refused("no execution token: every operation must pass through the gate")
        body = _token_body(op, target, amount, token["nonce"])
        if not hmac.compare_digest(hmac.new(self._key, body, hashlib.sha256).hexdigest(), str(token["tag"])):
            raise Refused("execution token does not match this operation, payee and amount")
        if token["nonce"] in self._spent:
            raise Refused("execution token already used")
        self._spent.add(token["nonce"])
        rec = {"op": op, "target": canon(target), "amount": float(amount)}
        self.executed.append(rec)
        return rec


class GatedPaymentAPI:
    """The only component holding the gate key. Agents call this; it decides, then mints a token for the backend."""

    def __init__(self, bank_key: bytes, gate_key: bytes, backend: PaymentBackend):
        self._bank_key, self._gate_key, self.backend = bank_key, gate_key, backend

    def _decide(self, op: str, s: Session, target: str, amount: float, new_value: str = "") -> Decision:
        if op == "pay":
            return decide_payment(target, amount, s)
        if op == "approve_collect":
            return decide_collect(target, amount, s)
        if op == "add_payee":
            return decide_add_beneficiary(target, s)
        if op == "update_payee":
            return decide_update_beneficiary(target, new_value, s)
        return decide_credential(target, s)

    def request(self, op: str, sealed: Tuple[bytes, str], target: str, amount: float = 0.0, new_value: str = "",
                confirm=None) -> Dict:
        """op: one of OPS. sealed: (state, seal) from the bank. confirm: callable(decision) -> bool, the customer's
        answer on a STEP_UP (None = no customer present, treated as decline)."""
        if op not in OPS:
            raise ValueError(op)
        s = open_session(*sealed, self._bank_key)          # raises UntrustedState for agent-made state
        d = self._decide(op, s, target, amount, new_value)
        go = d.verdict == ALLOW or (d.verdict == STEP_UP and confirm is not None and bool(confirm(d)))
        if not go:
            return {"decision": d, "executed": None}
        exec_target = new_value if op == "update_payee" else target
        nonce = secrets.token_hex(16)
        tag = hmac.new(self._gate_key, _token_body(op, exec_target, amount, nonce), hashlib.sha256).hexdigest()
        return {"decision": d, "executed": self.backend.execute(op, exec_target, amount, {"nonce": nonce, "tag": tag})}
