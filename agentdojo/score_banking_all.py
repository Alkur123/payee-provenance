"""PR52 (docs/PREREGISTRATION_52_payee_provenance_all_agentdojo.md): the frozen PR49 scorer on every banking run in
AgentDojo 089ed468, every configuration and attack type. Imports score_run/summarise unchanged; only walks more files.

    python eval/payee_provenance_all.py <agentdojo_repo_dir>
"""
from __future__ import annotations

import glob
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from score_banking import score_run, summarise, wilson  # noqa: E402  (frozen PR49 instrument, = backend/eval/payee_provenance.py)

DEFENDED = {"gpt-4o-2024-05-13-tool_filter", "gpt-4o-2024-05-13-transformers_pi_detector",
            "gpt-4o-2024-05-13-spotlighting_with_delimiting", "gpt-4o-2024-05-13-repeat_user_prompt",
            "meta-llama_Llama-3.3-70B-Instruct-repeat_user_prompt", "Meta-SecAlign-70B",
            "Meta-SecAlign-70B-repeat_user_prompt", "claude-3-sonnet-20240229-repeat_user_prompt"}


def rate(k, n):
    return {"k": k, "n": n, "pct": round(100 * k / n, 1) if n else None, "wilson95": wilson(k, n)}


def main():
    repo = sys.argv[1]
    out = pathlib.Path(__file__).parent / "results_pr52"
    out.mkdir(parents=True, exist_ok=True)
    benign, attack = [], []
    for cfg_dir in sorted(glob.glob(os.path.join(repo, "runs", "*", "banking"))):
        cfg = pathlib.Path(cfg_dir).parent.name
        for f in sorted(glob.glob(os.path.join(cfg_dir, "user_task_*", "*", "*.json"))):
            atype = pathlib.Path(f).parent.name
            d = json.load(open(f, encoding="utf-8"))
            row = {"cfg": cfg, "attack_type": atype, "file": os.path.relpath(f, repo), "calls": score_run(d),
                   "security": bool(d.get("security")), "utility": d.get("utility")}
            (benign if atype == "none" else attack).append(row)
    res = {"_what": "PR52: frozen PR49 scorer on all AgentDojo 089ed468 banking runs (recorded traces).",
           "configurations": sorted({r["cfg"] for r in benign + attack}),
           "pooled": {"benign_runs": len(benign), "attacked_runs": len(attack), **summarise(benign, attack)}}
    db = [r for r in benign if r["cfg"] in DEFENDED]
    da = [r for r in attack if r["cfg"] in DEFENDED]
    res["E2_defended_configs"] = {"configs": sorted(DEFENDED & set(res["configurations"])),
                                  "benign_runs": len(db), "attacked_runs": len(da), **summarise(db, da)}
    succ = [r for r in attack if r["security"]]
    res["success_runs_without_payment_or_credential_call"] = {
        "n": sum(1 for r in succ if not r["calls"]),
        "by_attack_type": {t: sum(1 for r in succ if not r["calls"] and r["attack_type"] == t)
                           for t in sorted({r["attack_type"] for r in succ})}}
    res["per_config"] = {c: summarise([r for r in benign if r["cfg"] == c], [r for r in attack if r["cfg"] == c])
                         for c in res["configurations"]}
    res["per_attack_type"] = {t: summarise([], [r for r in attack if r["attack_type"] == t])
                              for t in sorted({r["attack_type"] for r in attack})}
    json.dump(res, open(out / "results.json", "w"), indent=1)
    json.dump(benign + attack, open(out / "per_call.json", "w"))
    p = res["pooled"]
    for k in ("H1_success_runs_all_attacker_calls_stopped", "H3_success_runs_cap_lets_through",
              "H4_legit_benign_payee_gate_block", "H5_legit_benign_payee_allowlist_block", "H6_attacker_credential_blocked",
              "legit_payee_calls_inside_attacked_runs_gate_block"):
        print(k, p[k])
    print("success runs total", p["success_runs_total"], "with identified attacker call", p["success_runs_with_identified_attacker_call"])
    print("E2 defended", res["E2_defended_configs"]["H1_success_runs_all_attacker_calls_stopped"], res["E2_defended_configs"]["configs"])
    print("no payment/credential call in successful run:", res["success_runs_without_payment_or_credential_call"])


if __name__ == "__main__":
    main()
