# Pre-registration 54 (protocol only, NOT yet run): do people decline an attacker's payee on the provenance card?

**Written 2026-10-31.** This closes nothing by itself; it fixes the design before any participant exists, so the one number
the gate depends on (how often a customer approves a STEP_UP that serves an attacker) is measured, not assumed.

## Why
In every evaluation so far the STEP_UP answer was simulated (a "careful" customer and an "approves everything" worst case:
0/150 vs 10/150 attacks in the red team). The closest published evidence is Akesson, Gathergood & Quispe-Torreblanca (2023,
Nottingham CeDEx DP 2023-08, with the UK Open Banking Implementation Entity): in a randomised online experiment inside a
mobile banking app, a risk-based warning plus a salient call to action cut falling for fraud by 81% versus control (94% by
the third scenario), while generic behavioural warnings cut it by 18% and decayed with exposure. Our card follows the
winning design (risk-targeted, names the payee's source, defaults to Cancel, offers an out-of-band check). Their setting is
human-initiated UK payments; ours is an agent's proposal on UPI, so their effect size is a prior, not our result.

## Design
* Participants: adults in India who use UPI weekly; recruited through an online panel; target n = 300 (power for an 81% vs
  50% relative reduction at alpha 0.05 with margin), paid a fixed fee plus a bonus for each correct decision.
* Task: a semi-interactive mock banking app; an "assistant" proposes 10 payments built from our scenario catalogue (5
  legitimate, 5 attacker-serving; order randomised; Hindi or English by participant choice).
* Arms (between subjects, randomised): A no card (payment executes; participant can only review the history afterwards);
  B a generic "Are you sure?" confirm; C the provenance card (`confirmation_card()`), default Cancel.
* Primary outcome: share of attacker-serving proposals approved (lower is better). Secondary: share of legitimate proposals
  cancelled (friction); time on card; decay across the 5 attacker trials.

## Predictions
| id | prediction |
|---|---|
| H1 | C approves attacker-serving proposals at least 50% less often than B |
| H2 | C cancels legitimate proposals at most 10 percentage points more often than B |
| H3 | C's effect on attacker approvals does not decay between the first and last attacker trial (difference < 10 points) |

## Ethics and data
No real accounts, money or personal identifiers; all payees synthetic. Consent before participation; no deception about the
study's purpose beyond not saying which proposals are fraudulent. Analysis code and this file are published before data.

## Status
Not run. Owed before any claim about real customers' behaviour at the confirmation step.
