"""Coached human payments: the case provenance cannot see (the customer really typed the scammer's account).

Synthetic scenarios modelled on reported Indian fraud patterns; each lists the signals a banking app already has. We
measure what the policy DOES (hold / step-up / allow), not whether a held victim would cancel: that depends on people
and is not measured here.

    python evaluate_human.py
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from payee_provenance.gate import (ALLOW, BLOCK, HOLD, STEP_UP, Beneficiary, HumanContext, Session,  # noqa: E402
                                   decide_human_payment)

r = random.Random(55)


def base():
    s = Session(principal_messages=[], mandate_cap=20000.0)
    for p in ("mom.sharma@okaxis", "freshmart@axisbank", "r.iyer.rent@oksbi"):
        s.beneficiaries[p] = Beneficiary(p, "P", "saved")
    return s


def fam(name, kind, n, mk):
    return [(name, kind) + mk(i) for i in range(n)]


SC = []
# coached fraud (the payee was typed or pasted by the victim on a scammer's instructions)
SC += fam("H1_digital_arrest", "fraud", 10, lambda i: (f"safe.account{i}@ybl", r.choice([95000, 240000, 480000]),
          HumanContext("typed", True, True, 600000, 0)))
SC += fam("H2_fake_investment_pasted", "fraud", 10, lambda i: (f"tradeprofit{i}@paytm", r.choice([25000, 60000]),
          HumanContext("pasted", False, False, 150000, 40000)))
SC += fam("H3_impersonation_call", "fraud", 10, lambda i: (f"kyc.desk{i}@okicici", r.choice([4999, 19999]),
          HumanContext("typed", True, False, 90000, 0)))
SC += fam("H4_remote_access_refund", "fraud", 10, lambda i: (f"refund.help{i}@axl", r.choice([1, 9999, 49999]),
          HumanContext("typed", False, True, 80000, 0)))
SC += fam("H5_drain_new_payee_no_signal", "fraud", 10, lambda i: (f"loan.agent{i}@ybl", r.choice([70000, 90000]),
          HumanContext("typed", False, False, 120000, 0)))
SC += fam("H6_coached_earlier_small_no_signal", "fraud", 10, lambda i: (f"taskjob{i}@ybl", r.choice([500, 2000, 9000]),
          HumanContext("typed", False, False, 150000, 0)))       # hard case: no live signal, small, under the cap
# legitimate human payments
SC += fam("L_family_while_on_call", "legit", 10, lambda i: ("mom.sharma@okaxis", r.choice([2000, 5000]),
          HumanContext("saved", True, False, 80000, 0)))
SC += fam("L_shop_qr", "legit", 10, lambda i: ("freshmart@axisbank", r.choice([240, 900]),
          HumanContext("qr_in_person", False, False, 50000, 0)))
SC += fam("L_new_friend_typed_small", "legit", 10, lambda i: (f"friend{i}@okaxis", r.choice([300, 1200]),
          HumanContext("typed", False, False, 60000, 0)))
SC += fam("L_rent_known", "legit", 10, lambda i: ("r.iyer.rent@oksbi", 18000.0, HumanContext("saved", False, False, 70000, 0)))
SC += fam("L_large_new_payee_no_signal", "legit", 10, lambda i: (f"carseller{i}@hdfcbank", 30000.0,
          HumanContext("typed", False, False, 400000, 0)))
SC += fam("L_new_payee_while_dealer_calls", "legit", 10, lambda i: (f"cardealer{i}@icici", 250000.0,
          HumanContext("typed", True, False, 900000, 0)))           # hard case: genuine, but looks coached


def main():
    rows = {}
    for name, kind, payee, amt, ctx in SC:
        d = decide_human_payment(payee, float(amt), base(), ctx)
        rows.setdefault((name, kind), {ALLOW: 0, STEP_UP: 0, HOLD: 0, BLOCK: 0})[d.verdict] += 1
    print(f"{'family':32s} {'kind':6s} ALLOW STEP_UP HOLD")
    tot = {"fraud": [0, 0], "legit": [0, 0]}
    for (name, kind), c in rows.items():
        print(f"{name:32s} {kind:6s} {c[ALLOW]:5d} {c[STEP_UP]:7d} {c[HOLD]:4d}")
        tot[kind][0] += c[ALLOW]
        tot[kind][1] += sum(c.values())
    print(f"\ncoached fraud paid instantly: {tot['fraud'][0]}/{tot['fraud'][1]}   "
          f"legitimate paid instantly: {tot['legit'][0]}/{tot['legit'][1]}")


if __name__ == "__main__":
    main()
