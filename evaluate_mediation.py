"""Run the red team through the full integration path (bank-sealed state -> gate -> execution token -> backend), and try
three bypasses on every attacker action: call the backend directly, replay a used token, and redirect a token.

    python evaluate_mediation.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from payee_provenance.bank_api import GatedPaymentAPI, PaymentBackend, Refused, seal_session  # noqa: E402
from payee_provenance.gate import record_beneficiary  # noqa: E402
from payee_provenance.scenarios import build  # noqa: E402

BANK, GATE = b"bank-key-for-evaluation-only-32b", b"gate-key-for-evaluation-only-32b"
OP = {"pay": "pay", "approve_collect": "approve_collect", "add_beneficiary": "add_payee",
      "update_beneficiary": "update_payee", "set_credential": "set_password"}


def main():
    att_exec = att_total = leg_done = leg_total = 0
    bypass = {"direct call": [0, 0], "token replay": [0, 0], "token redirected": [0, 0]}
    for sc in build():
        s = sc.session
        backend = PaymentBackend(GATE)
        api = GatedPaymentAPI(BANK, GATE, backend)
        tokens = []
        real = backend.execute

        def spy(op, target, amount=0.0, token=None, _real=real):
            tokens.append((op, target, amount, token))
            return _real(op, target, amount, token)
        backend.execute = spy
        ok_all = True
        for a in sc.actions:
            op = OP[a.op]
            careful = (lambda d, atk=a.attacker: not atk)          # the customer who reads the confirmation
            target, new = (a.old, a.payee) if op == "update_payee" else (a.payee, "")
            out = api.request(op, seal_session(s, BANK), target, a.amount, new_value=new, confirm=careful)
            done = out["executed"] is not None
            if a.attacker:
                att_total += 1
                att_exec += done
                b = bypass["direct call"]; b[1] += 1
                try:
                    real(op, new or target, a.amount)
                except Refused:
                    b[0] += 1
            else:
                ok_all &= done
            if done and op in ("add_payee", "update_payee"):
                record_beneficiary(s, new or target, out["decision"])
        if any(not a.attacker for a in sc.actions):
            leg_total += 1
            leg_done += ok_all
        for op, target, amount, tok in tokens:                     # every token the gate minted in this scenario
            for name, args in (("token replay", (op, target, amount, tok)),
                               ("token redirected", (op, "attacker.redirect@ybl", amount, dict(tok, nonce=tok["nonce"] + "x")))):
                b = bypass[name]; b[1] += 1
                try:
                    real(*args)
                except Refused:
                    b[0] += 1
    print(f"through the full API path: attacker actions executed {att_exec}/{att_total}; "
          f"legitimate scenarios completed {leg_done}/{leg_total}")
    for k, (refused, n) in bypass.items():
        print(f"bypass attempt '{k}': refused {refused}/{n}")


if __name__ == "__main__":
    main()
