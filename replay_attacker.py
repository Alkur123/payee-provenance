"""Replay every gated tool call recorded in a PR56 adaptive-attacker run through the CURRENT gate, on the session the
attacker actually produced (its rewritten channels), and compare verdicts. Same logic as replay_closed_loop.py.

    python replay_attacker.py adaptive_attacker_v32.jsonl
"""
import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from adaptive_attacker import apply_channels  # noqa: E402
from closed_loop import gate_decide  # noqa: E402
from payee_provenance.gate import ALLOW, BLOCK, STEP_UP, Decision, record_beneficiary  # noqa: E402
from payee_provenance.scenarios import build  # noqa: E402


def main(path):
    scen = {sc.sid: sc for sc in build()}
    calls = same = 0
    diffs = []
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        for cust, rounds in r["rounds"].items():
            for x in rounds:
                s = copy.deepcopy(apply_channels(scen[r["sid"]], x["channels"]).session)
                for ev in x.get("all_events", x["attacker_events"]):
                    d = gate_decide(ev["tool"], ev["args"], s)
                    calls += 1
                    if d.verdict == ev.get("verdict"):
                        same += 1
                    else:
                        diffs.append((r["sid"], cust, x["round"], ev["tool"], ev["args"], ev.get("verdict"), d.verdict))
                    ok = ev.get("verdict") != BLOCK and (ev.get("verdict") != STEP_UP or ev.get("customer_confirmed"))
                    if ok and ev["tool"] in ("add_payee", "update_payee"):
                        record_beneficiary(s, ev["args"].get("payee") or ev["args"].get("new") or "",
                                           Decision(ALLOW, ev.get("cls", "UNKNOWN"), "", []))
    print(f"{path}: {same}/{calls} recorded attacker-serving calls get the same verdict from the current gate")
    for d in diffs:
        print("  DIFF", d)
    return not diffs


if __name__ == "__main__":
    sys.exit(0 if main(sys.argv[1]) else 1)
