"""Run every scenario under four controls and print the comparison table.

  none       no control beyond PIN/OTP (the agent already holds the session)
  cap        mandate cap: a payment passes if amount <= cap (UPI Reserve Pay / Circle shape)
  allowlist  a payment passes only to an existing beneficiary; adding a beneficiary is allowed (agent has the session)
  gate       payee provenance; STEP_UP is resolved two ways:
               gate_careful : the customer approves legitimate step-ups and declines attacker ones
               gate_fooled  : the customer approves EVERY step-up (worst case: they confirm without reading)

Attack succeeds if any attacker action executes. Legitimate scenario succeeds if every action executes; friction =
it needed at least one confirmation (or, for the baselines, a manual override because it was refused).

    python evaluate.py [--json out.json]
"""
from __future__ import annotations

import argparse
import copy
import json
import math
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from payee_provenance.gate import (ALLOW, BLOCK, STEP_UP, Beneficiary, canon, decide_add_beneficiary,  # noqa: E402
                                   decide_collect, decide_credential, decide_payment, decide_update_beneficiary)
from payee_provenance.receipt import ReceiptChain  # noqa: E402
from payee_provenance.scenarios import build  # noqa: E402

POLICIES = ["none", "cap", "allowlist", "gate_careful", "gate_fooled"]


def baseline(policy, act, s):
    if policy == "none":
        return True
    if act.op in ("pay", "approve_collect"):
        if policy == "cap":
            return act.amount <= s.mandate_cap
        if policy == "allowlist":
            return canon(act.payee) in s.beneficiaries
    if act.op in ("add_beneficiary", "update_beneficiary"):
        s.beneficiaries[canon(act.payee)] = Beneficiary(canon(act.payee), "UNKNOWN", "added in session")
    return True


def gate_step(policy, act, s, chain):
    if act.op == "pay":
        d = decide_payment(act.payee, act.amount, s)
    elif act.op == "approve_collect":
        d = decide_collect(act.payee, act.amount, s)
    elif act.op == "add_beneficiary":
        d = decide_add_beneficiary(act.payee, s)
    elif act.op == "update_beneficiary":
        d = decide_update_beneficiary(act.old, act.payee, s)
    else:
        d = decide_credential(act.payee, s)
    confirmed = None
    if d.verdict == STEP_UP:
        confirmed = (not act.attacker) if policy == "gate_careful" else True
    executed = d.verdict == ALLOW or (d.verdict == STEP_UP and confirmed)
    if executed and act.op in ("add_beneficiary", "update_beneficiary"):
        s.beneficiaries[canon(act.payee)] = Beneficiary(canon(act.payee), "D_CONFIRMED" if d.payee_class == "D"
                                                        else d.payee_class, "added in session",
                                                        recently_changed=act.op == "update_beneficiary")
    chain.append(agent_id="agent-demo", mandate_id="RP-001", mandate_version=1,
                 instruction=" | ".join(s.principal_messages), payee=act.payee, amount=act.amount,
                 payee_class=d.payee_class, source=d.source, verdict=d.verdict, confirmed_by_customer=confirmed, ts=0)
    return executed, d.verdict == STEP_UP, d


def run(scenarios, registry=True):
    rows = []
    chain = ReceiptChain(secrets.token_bytes(32))
    for sc in scenarios:
        row = {"sid": sc.sid, "family": sc.family, "kind": sc.kind}
        for pol in POLICIES:
            s = copy.deepcopy(sc.session)
            if not registry:
                s.biller_registry = {}
            att_exec, att_instant, legit_ok, friction, verdicts = False, False, True, False, []
            for act in sc.actions:
                if pol.startswith("gate"):
                    ok, stepped, d = gate_step(pol, act, s, chain)
                    verdicts.append(d.verdict)
                    friction |= stepped
                else:
                    ok, stepped = baseline(pol, act, s), False
                if act.attacker and ok:
                    att_exec = True
                    if not (pol.startswith("gate") and stepped):
                        att_instant = True     # a confirmed STEP_UP is released only after a cancellable hold
                if not act.attacker and not ok:
                    legit_ok = False
            row[pol] = {"attack_succeeded": att_exec, "attack_paid_instantly": att_instant,
                        "legit_completed": legit_ok, "friction": friction,
                        "verdicts": verdicts}
        rows.append(row)
    return rows, chain


def wilson(k, n):
    if not n:
        return (None, None)
    z, p = 1.96, k / n
    den = 1 + z * z / n
    c, h = (p + z * z / (2 * n)) / den, z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return (round(100 * (c - h), 1), round(100 * (c + h), 1))


def summarise(rows):
    att = [r for r in rows if r["kind"] == "attack"]
    leg = [r for r in rows if r["kind"] == "legit"]
    summ = {}
    for pol in POLICIES:
        a = sum(r[pol]["attack_succeeded"] for r in att)
        ai = sum(r[pol]["attack_paid_instantly"] for r in att)
        lc = sum(r[pol]["legit_completed"] for r in leg)
        fr = sum(r[pol]["friction"] for r in leg)
        summ[pol] = {"attack_paid_instantly": f"{ai}/{len(att)}", "attack_success": f"{a}/{len(att)}", "attack_success_pct": round(100 * a / len(att), 1),
                     "attack_ci95": wilson(a, len(att)), "legit_completed": f"{lc}/{len(leg)}",
                     "legit_completed_pct": round(100 * lc / len(leg), 1), "legit_friction": f"{fr}/{len(leg)}"}
    fam = {}
    for r in rows:
        f = fam.setdefault(r["family"], {p: 0 for p in POLICIES} | {"n": 0, "kind": r["kind"]})
        f["n"] += 1
        for p in POLICIES:
            f[p] += r[p]["attack_succeeded"] if r["kind"] == "attack" else r[p]["legit_completed"]
    return summ, fam


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    ap.add_argument("--no-registry", action="store_true", help="v1 gate: provenance only, no biller registry")
    a = ap.parse_args()
    rows, chain = run(build(), registry=not a.no_registry)
    summ, fam = summarise(rows)
    print(f"{'family':28s} {'n':>3s}  " + "  ".join(f"{p:>12s}" for p in POLICIES))
    for name, f in fam.items():
        label = "attacks succeeded" if f["kind"] == "attack" else "legit completed"
        print(f"{name:28s} {f['n']:3d}  " + "  ".join(f"{f[p]:12d}" for p in POLICIES) + f"   ({label})")
    print()
    for p, v in summ.items():
        print(f"{p:13s} attack success {v['attack_success']:>8s} ({v['attack_success_pct']}%, CI {v['attack_ci95']})"
              f"   of which paid instantly {v['attack_paid_instantly']:>8s}   legit completed {v['legit_completed']:>8s}   legit friction {v['legit_friction']}")
    print(f"\nreceipt chain: {len(chain.entries)} receipts, verifies = {chain.verify()}")
    if a.json:
        json.dump({"summary": summ, "families": fam, "rows": rows}, open(a.json, "w"), indent=1, ensure_ascii=False)


if __name__ == "__main__":
    main()
