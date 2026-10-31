"""Replay every gated tool call recorded in the closed-loop runs through the CURRENT gate and compare verdicts.

The closed-loop episodes were run with gate v3.0. If v3.1 returns the same verdict on every recorded call, in order and
with the same session updates, each agent would have seen the same responses and taken the same path, so the recorded
results hold for v3.1 without re-running the models.

    python replay_closed_loop.py closed_loop.jsonl closed_loop_gptoss.jsonl closed_loop_gpt41mini.jsonl
"""
import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from closed_loop import gate_decide  # noqa: E402
from payee_provenance.gate import ALLOW, BLOCK, STEP_UP, Decision, record_beneficiary  # noqa: E402
from payee_provenance.scenarios import build  # noqa: E402


def replay(path):
    scen = {sc.sid: sc for sc in build()}
    calls = same = 0
    diffs = []
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        if not r["gated"] or r["error"]:
            continue
        s = copy.deepcopy(scen[r["sid"]].session)
        for ev in r["events"]:
            d = gate_decide(ev["tool"], ev["args"], s)
            calls += 1
            if d.verdict == ev.get("verdict"):
                same += 1
            else:
                diffs.append((r["sid"], ev["tool"], ev["args"], ev.get("verdict"), d.verdict))
            ok = ev.get("verdict") != BLOCK and (ev.get("verdict") != STEP_UP or ev.get("customer_confirmed"))
            if ok and ev["tool"] in ("add_payee", "update_payee"):
                record_beneficiary(s, ev["args"].get("payee") or ev["args"].get("new") or "",
                                   Decision(ALLOW, ev.get("cls", "UNKNOWN"), "", []))
    print(f"{path}: {same}/{calls} recorded gated calls get the same verdict from the current gate")
    for d in diffs:
        print("  DIFF", d)
    return not diffs


if __name__ == "__main__":
    results = [replay(p) for p in sys.argv[1:]]
    sys.exit(0 if all(results) else 1)
