"""Signed provenance receipts.

A dispute over an agent payment needs to answer: which agent acted, under which mandate version, against what customer
instruction, and who supplied the payee. RBI's directions of 24 June 2026 (effective 1 January 2027) add an
"authorised-but-fraudulent" category and place the burden of proof on the bank. This receipt is that proof, written at
payment time rather than reconstructed afterwards.

Each receipt carries the hash of the previous one and an HMAC under a key the agent never holds, so a party that can
write the receipt store still cannot rewrite history without detection (the same design as Aegis' audit vault).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import List, Optional


class ReceiptChain:
    def __init__(self, key: bytes):
        if len(key) < 32:
            raise ValueError("signing key must be at least 32 bytes")
        self._key = key
        self.entries: List[dict] = []

    def _mac(self, body: dict) -> str:
        msg = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()

    def append(self, *, agent_id: str, mandate_id: str, mandate_version: int, instruction: str, payee: str,
               amount: float, payee_class: str, source: str, verdict: str, confirmed_by_customer: Optional[bool] = None,
               ts: Optional[float] = None) -> dict:
        prev = self.entries[-1]["mac"] if self.entries else "0" * 64
        body = {
            "seq": len(self.entries), "ts": ts if ts is not None else time.time(), "agent_id": agent_id,
            "mandate_id": mandate_id, "mandate_version": mandate_version,
            "instruction_sha256": hashlib.sha256(instruction.encode()).hexdigest(),
            "payee": payee, "amount": amount, "payee_class": payee_class, "payee_source": source,
            "verdict": verdict, "confirmed_by_customer": confirmed_by_customer, "prev": prev,
        }
        rec = dict(body, mac=self._mac(body))
        self.entries.append(rec)
        return rec

    def verify(self) -> bool:
        prev = "0" * 64
        for i, rec in enumerate(self.entries):
            body = {k: v for k, v in rec.items() if k != "mac"}
            if body.get("seq") != i or body.get("prev") != prev:
                return False
            if not hmac.compare_digest(self._mac(body), rec["mac"]):
                return False
            prev = rec["mac"]
        return True

    def dispute_category(self, seq: int) -> str:
        """Where a disputed payment stands, read off the receipt alone. This is OUR mapping for a dispute desk, not an
        RBI category; the RBI 2026 directions leave classification to the bank's board-approved policy."""
        r = self.entries[seq]
        v, c, conf = r["verdict"], r["payee_class"], r["confirmed_by_customer"]
        if v == "BLOCK" or (v == "STEP_UP" and conf is False):
            return "PREVENTED: no money moved"
        if v == "STEP_UP" and conf:
            return "CUSTOMER-CONFIRMED: the customer approved after being shown the payee's source"
        if c in ("P", "K", "R"):
            return "CUSTOMER-SUPPLIED: the payee came from the customer, their saved record, or the biller registry"
        return "CONTROL FAILURE: an unsourced payee was paid; the gate did not operate as designed"

    def dispute_report(self) -> dict:
        """Counts per category, after verifying the chain. An unverifiable chain is reported, never summarised."""
        if not self.verify():
            return {"chain_verified": False}
        out: dict = {"chain_verified": True}
        for i in range(len(self.entries)):
            k = self.dispute_category(i).split(":")[0]
            out[k] = out.get(k, 0) + 1
        return out

    def liability_view(self, seq: int) -> str:
        """Plain-language reading of one receipt, for a dispute desk or an ombudsman."""
        r = self.entries[seq]
        who = {"P": "the customer typed this payee", "K": "the payee was already a beneficiary created by the customer",
               "D": "the payee came from a document the customer pointed the agent to",
               "W": "the payee came from outside the customer's instruction"}[r["payee_class"]]
        out = {"ALLOW": "paid", "STEP_UP": "held for the customer's confirmation", "BLOCK": "refused"}[r["verdict"]]
        conf = "" if r["confirmed_by_customer"] is None else (
            " The customer confirmed it." if r["confirmed_by_customer"] else " The customer declined it.")
        return (f"Receipt {seq}: agent {r['agent_id']} under mandate {r['mandate_id']} v{r['mandate_version']} "
                f"proposed {r['amount']} to {r['payee']}; {who} ({r['payee_source']}). Outcome: {out}.{conf}")
