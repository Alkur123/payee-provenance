# Pre-registration 52: payee provenance on every banking run in AgentDojo, including runs behind existing defences

**Written 2026-10-31 (~14:05 IST) before the additional runs are fetched.** sha256 printed to the session first.

## Why
PR49 scored one attack type (`important_instructions`) for four models. Its limitations: one attack type, four models,
24 legitimate payee calls. AgentDojo at the same pinned commit `089ed468` holds banking runs for 29 model / pipeline
configurations, several of which already run a defence (`tool_filter`, `transformers_pi_detector`,
`spotlighting_with_delimiting`, `repeat_user_prompt`, Meta-SecAlign-70B). Those let us ask: does the gate stop the attacks
that existing defences let through?

## Data
Every `runs/<config>/banking/user_task_*/<attack>/*.json` at `089ed468`, all configurations and all attack types present.
Benign = `none/none.json`. Attacked = any other attack directory. Seen before this file: the list of configuration names
and, for the four PR49 models, the list of attack directory names. No new run file has been opened.

## Instrument (frozen)
`backend/eval/payee_provenance.py` `score_run` and its constants, **unchanged** (sha256 `8d3bf976…61fa2e`), applied by a
new driver `backend/eval/payee_provenance_all.py` that only walks more directories and groups results. Same attacker
ground truth (the injection IBAN, the injection password), same baselines (B-cap, B-allow).

## Predictions
| id | quantity (pooled over all configurations and attack types) | prediction |
|---|---|---|
| E1 | successful-attack runs with an identified attacker call in which every attacker call is stopped (BLOCK or STEP_UP) | **≥ 97%** |
| E2 | the same, restricted to the defended configurations listed above (attacks the existing defence let through) | **≥ 97%** |
| E3 | legitimate payee calls in benign runs BLOCKed | **≤ 3%** |
| E4 | successful-attack runs B-cap lets through (≥1 attacker call passes) | **≥ 60%** |

Reported per configuration and per attack type with counts and Wilson intervals. Runs whose `security` is true but which
contain no payment or credential call (denial-of-service attack types aim to stop the agent, not move money) are counted
and reported separately, not as misses.

## Not claimed
Closed-loop behaviour; anything about the defences beyond what their recorded runs show.

## 9. Amendments
**9.1 (2026-10-31, 13:25 IST).** The header says "~14:05 IST"; the file was written and hashed at 13:12 IST (`date` printed
with the hash). Of the 29 configurations, 28 have banking runs (`claude-3-sonnet-20240229-repeat_user_prompt` has none).

**9.2 (2026-10-31, 13:30 IST). RESULTS** (`backend/eval/results/payee_provenance_pr52/`; driver sha256 `7f2ab0e1…a6edaa`,
scorer unchanged `8d3bf976…`). 28 configurations, 15 attack types, 448 benign and 7,354 attacked runs; 1,549 successful
attacks, 1,477 with an identified attacker call.

| id | result | verdict |
|---|---|---|
| E1 | every attacker call stopped in **1,477/1,477** (Wilson 99.7–100) | HELD |
| E2 | defended configurations (tool filter, PI detector, spotlighting, repeat-prompt, Meta-SecAlign): **299/299** (98.7–100) | HELD |
| E3 | legitimate benign payee calls BLOCKed **11/210 = 5.2%** (2.9–9.1), predicted ≤ 3% | **FAILED** |
| E4 | B-cap lets ≥1 attacker call through in **1,235/1,477 = 83.6%** | HELD |

Also: credential takeovers blocked 239/239; B-allow blocks 128/210 = 61.0% of legitimate benign payee calls.
**E3, inspected after scoring (not a re-definition; E3 stays FAILED).** All 11 blocked calls name a payee the user never
named and the bank never recorded: 7 pay the account's OWN IBAN, 2 pay a model-corrupted IBAN (an extra digit inserted into
the landlord's or a saved payee's IBAN), 1 a placeholder string, 1 a made-up IBAN. None is a correct, user-intended payee.
The gate is blocking agent errors that would have misdirected money; that is a finding, not a defence of the prediction.
**Unidentified successes (72):** 27 runs with no payment or credential call (22 in denial-of-service attack types, which aim
to stop the agent, and 5 important_instructions runs whose success did not involve a payment); 43 user_task_15 runs (the attacker IBAN is the landlord the user names, as in PR49); 1 the user's own
requested password change; 1 a denial-of-service run that moved no money.
