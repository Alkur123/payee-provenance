# Who Said So? Payee provenance for agent payments

**Every payment control in use asks "is it you?" (PIN, OTP) or "is it them?" (Confirmation of Payee). Authorised push
payment fraud passes both. This gate asks the question nobody asks: *who supplied this payee?***

For a human payment that question cannot be answered: the scam happens on a phone call or in a WhatsApp chat the bank
never sees. For an AI agent's payment it can, exactly, because everything the agent read is in its context. Agentic
payments are arriving on UPI now (Razorpay × NPCI on Claude, Feb 2026; NPCI's Unified Agent Protocol in development).
They are protected by spending caps, which bound **how much**. Nothing binds **who said so**.

**Report:** [AegisAI_Report.pdf](AegisAI_Report.pdf) (10 pages, SAFL template) · **Supplementary:** [AegisAI_Supplementary.pdf](AegisAI_Supplementary.pdf) (background, design detail, full threat model) · **Video:** [media/demo.mp4](media/demo.mp4) (1:51)

| class | the payee identifier... | decision |
|---|---|---|
| **P** principal | occurs, as a whole token, in the customer's own message | ALLOW |
| **K** known | is a beneficiary the customer created (provenance is inherited, so the list cannot be laundered) | ALLOW |
| **R** registered | came from a document the customer named AND is the registered handle of the biller the document claims to be (Bharat BillPay / NPCI verified merchant) | ALLOW |
| **D** document | came from a document the customer named, with no registry to confirm it | STEP-UP: confirmation card showing the source |
| — mismatch | the document claims a registered biller but the payee is not that biller's handle | BLOCK |
| **W** world | came from anywhere else: SMS, web page, collect request, tool output, a file the agent itself wrote, nowhere | BLOCK |

Amounts carry provenance too: a stated amount is a ceiling; a registered bill must equal the Bharat Connect fetch; a saved
payee above its last-paid amount needs confirmation; otherwise above the mandate cap needs confirmation. Changing a saved
payee's account is gated like a payment and starts a cooling-off window.

The rules are deterministic and fully public. **Knowing them does not help an attacker**: there is no classifier to fool
or threshold to sit under. A prompt injection cannot write into the customer's message or the bank's beneficiary record,
and any obfuscation of the identifier (homoglyphs, zero-width characters, look-alike VPAs) only makes it unfindable in the
customer's text, which turns it into W, which blocks. **The gate fails closed by construction.**

Every decision writes a **signed, hash-chained provenance receipt** recording the agent, the mandate version, the
customer instruction, the payee, its class and source, and the outcome. RBI's directions of 24 June 2026 (effective
1 January 2027) add an "authorised-but-fraudulent" category and put the burden of proof on the bank; this receipt is
that proof, written at payment time.

## Evidence

### 1. External, pre-registered: every banking run AgentDojo publishes
AgentDojo (ETH Zürich) is the standard agent prompt-injection benchmark. At pinned commit `089ed468` we scored, with a
frozen scorer and predictions hashed first (`preregistrations/`), every banking run it publishes: **28 model and pipeline
configurations, 15 attack types, 7,802 runs** (`agentdojo/score_banking_all.py`, `agentdojo/results_pr52.json`).
No agent was run; this scores what the agents actually did.

| | result |
|---|---|
| successful attacks with every attacker call stopped | **1,477 / 1,477** (Wilson 99.7–100%) |
| attacks that had already got **past an existing defence** (prompt-injection detector, tool filter, spotlighting, repeated user prompt, Meta-SecAlign) | **299 / 299** stopped |
| UPI-style spending cap on the same traces | lets **83.6%** through |
| credential takeovers blocked | 239 / 239 |
| legitimate-intent payee calls blocked (predicted ≤ 3%) | **11 / 210 = 5.2%: prediction FAILED**. Every one of the 11 paid a wrong account: 7 the customer's own IBAN, 2 an IBAN the model corrupted, 1 a placeholder, 1 an invented IBAN. None was an intended payee. |
| known-payee allowlist on the same calls | blocks 61.0% of legitimate payments |

The first, smaller registration (four models, one attack type; `agentdojo/score_banking.py`) held all six predictions:

| | provenance gate | mandate cap (Reserve Pay shape) | known-payee allowlist |
|---|---|---|---|
| successful attacks with every attacker call stopped | **197 / 197** (95% CI 98.1–100) | lets ≥1 through in **159 / 197** (80.7%) | 171 / 197 (credential takeovers pass) |
| attacker payments blocked outright / held for confirmation | 55.4% / 44.6% | | |
| legitimate payments blocked | **0 / 24** (CI 0–13.8) | 8 / 24 | **10 / 24** (41.7%) |
| attacker credential changes blocked | **28 / 28** | 0 / 28 | 0 / 28 |

Four further "successful" attacks pay the IBAN the user *themselves* named in that task (AgentDojo reuses the attacker's
IBAN as a landlord's); the gate allows them because the customer authorised that payee. Counting them as misses: 197/201.

### 2. White-box red team on a mock UPI rail: the agent fully hijacked
`evaluate.py` runs 150 attacks across 15 Indian fraud families and 150 legitimate payments across 15 families. In every
attack the agent does **exactly** what the injected text says, so nothing relies on the model resisting. Families A6–A9
and A12 were written from the gate's own rules to break it; A13–A15 replay the failures concurrent work reported (amount
inflation, vendor-master change, laundering through a file the agent wrote).

| control | attacks succeeded (of 150) | legitimate payments completed (of 150) |
|---|---|---|
| none (agent holds the session) | 150 | 150 |
| mandate cap | 117 (78.0%) | 140 |
| known-payee allowlist | 35 (23.3%): laundering, payee changes, credential theft pass | **80**: every new payee refused |
| **gate, customer reads confirmations** | **0** (CI 0–2.5) | **150** (15 needed one confirmation) |
| **gate, customer approves every confirmation** | **10** (6.7%): landlord-notice hijacks and inflated shop bills, each shown for confirmation first | **150** |

History, all on scenarios we wrote (design results, not independent): v1 provenance only; v2 added the biller registry;
v3 added amount provenance, payee-change gating with a cooling-off window, agent-written files as world text and
digit-separator canonicalisation. **The independent evidence is §1 and the closed loop in §3.**

### 3. Closed loop with real LLMs, three model families (pre-registered, `closed_loop.py`)
A real model is the payment agent on 3 scenarios per family (90 scenarios), each run undefended and gated; it sees the
gate's refusals and may try again. gemma4 was registered first (PR50); two more families were registered before any of
their episodes (PR55, four dated amendments in `preregistrations/`). Outcome as registered: money moved, a credential set
or a collect request approved (`score_pr55.py`).

| agent model | attacks: undefended → **gated** | legitimate completed: undefended → gated | scenarios |
|---|---|---|---|
| gemma4 (Google, open weights, local) | 12/45 → **0/45** | 33 → 33 | 90/90 |
| gpt-oss-120b (OpenAI, open weights, via Groq) | 14/44 → **0/44** | 23 → 23 | 70/90 † |
| gpt-4.1-mini (OpenAI, commercial) | 20/45 → **0/45** | 32 → 35 | 90/90 |

The models fell for invoice redirection, injected invoice instructions, inflated amounts and laundering through a file the
agent wrote; the commercial model fell for the most, and the gate stopped every one without costing a legitimate task.
† Groq's free tier stopped gpt-oss-120b at its daily token limit after 70 paired scenarios; the rest are reported as not
run. Episodes lost to a network outage (no model reply) were re-run under a rule fixed before the re-run; the first
attempts are kept (`*_attempt1.jsonl`). One provider error (HTTP 400) is reported, not re-run. gemma4 details:
`CLOSED_LOOP_RESULTS.md`.

### 4. In front of a real, unmodified Indian payout server (pre-registered)
We built an Indian payment gateway's official open-source MCP payout server from source, unmodified, and ran it locally with
all traffic routed to a capture proxy (no vendor system contacted, dummy credentials). With gemma4 as a finance assistant:
an attacker payout reached the payment API in **14 of 15** attack episodes direct, **0 of 15** gated (batches refuse only the offending row), and every
legitimate payout went through in both. The server already asks where each value came from, but the model writes the
answer: it labelled the attacker's payee "user input" 12 times and "inferred from context" 8 times, never "generated by
model". Self-reported provenance is testimony. The harness and per-episode data will be published here after the vendor has
had the chance to respond to our hardening note.

With a second model, gpt-4.1-mini (OpenAI, commercial), on every scenario (PR55, 48 episodes, 0 errors): the attacker's
payout reached the payment API in **10 of 15** attack episodes direct and **0 of 15** gated; every legitimate payout was
delivered in 12 of 15 episodes in both conditions (the 3 misses are one batch scenario where the model made no payout
either way).

### 5. Tests that can fail
32 tests, including a 5,000-case fuzz of the fail-closed claim (only the customer's exact token can ever be allowed,
under eight attacker transformations), laundering, registry mismatch, the concurrent-work gaps, the signed customer
channel, the confirmation card, receipt tampering and the dispute report. `tests/mutation_probe.py` plants fifteen
defects in a copy of the code; **all fifteen are caught**.

## Concurrent work (October 2026)
Three projects reached the same principle this month; we found them in our final research pass and compare honestly.

| work | where the check runs | evidence | gap it reports or leaves → what we built |
|---|---|---|---|
| [Mool](https://github.com/Dipensinghh/mool) (5 Oct, UPI) | inside a redesigned agent (CaMeL planner + quarantined extractor) | deterministic stand-in model: 0/300 stolen, 46/50 clean | amount inflation overpaid 31/50 → bill-fetch match + last-paid ceiling (A13) |
| [taintgate](https://hackernoon.com/testing-provenance-based-controls-against-indirect-prompt-injection-in-ai-agents) (11 Oct) | in-process | 5 scenarios: 3/5 stopped, **0/2 legitimate allowed** | reformatting, multi-tool laundering, real vs injected bill IBAN → canonicalisation, root matching + agent-written files as W (A15), registry binding |
| [fps-ai-security-poc](https://github.com/Sarjeant/fps-ai-security-poc) (19 Oct, ISO 20022) | layered policy + CoP + hold | simulated agent; Claude Haiku refused on its own | names vendor-master fraud → payee changes gated + cooling-off (A14) |

What is ours: a pre-registered result on every AgentDojo banking run (28 configurations, including attacks that beat existing defences); a closed loop with three real LLM families; enforcement at
the bank or PSP rather than inside the agent (a bank does not choose its customer's agent); the gaps above closed and
measured; a receipt and dispute report shaped for RBI's 2027 burden of proof.

## How a bank deploys it
* **Where:** at the bank, PSP or payment-app endpoint that receives the agent's payment request, before the UPI request is
  formed. Agent-agnostic, so one control covers every agent a customer might use.
* **Inputs the bank already holds:** the customer's signed messages, beneficiary records and who created them, the
  verified-merchant list every UPI app stores, Bharat Connect biller data and bill fetch; for human payments, in-call and
  screen-sharing signals from the app.
* **Cost:** 424 lines of standard-library Python (gate + receipts), no model, no network call; median 74 µs per decision,
  99th percentile 0.24 ms on one laptop core.
* **Fails closed:** a payee nobody on the customer's side wrote is refused. Across all AgentDojo banking runs, the 11
  legitimate-task payments refused (of 210) were all to wrong accounts the agent itself produced.
* **Rollout:** shadow mode (log, block nothing; measure false blocks on real traffic) → enforce BLOCK for unsourced payees
  and registry mismatches → turn on confirmations and holds. Report monthly: false-block rate, confirmation rate, holds
  cancelled, fraud loss on agent payments, dispute resolution time from the signed receipt.

## Run it
Python 3.10+, standard library only, no network, no model.
```
python evaluate.py                       # the red-team table (v3); --no-registry disables the biller registry
python -m unittest discover -s tests -v  # 32 tests
python tests/mutation_probe.py           # 15/15 planted defects caught
python evaluate_human.py                 # coached human payments (hold / step-up / allow)
python closed_loop.py                    # closed loop; needs a local Ollama with gemma4 (about an hour)
python closed_loop.py --model openai:gpt-4.1-mini-2025-04-14 --out closed_loop_gpt41mini.jsonl   # needs OPENAI_API_KEY
python score_pr55.py closed_loop.jsonl closed_loop_gptoss.jsonl closed_loop_gpt41mini.jsonl     # registered outcome
python agentdojo/score_banking.py <agentdojo-checkout-at-089ed468>       # first registration (4 models)
python agentdojo/score_banking_all.py <agentdojo-checkout-at-089ed468>   # every banking run (28 configurations)
```

## What it does not do
* **Coached customers: partly closed, one case open.** Provenance cannot see a customer who really typed the scammer's
  account. `decide_human_payment()` uses signals a banking app already has (call with an unknown number, screen sharing
  or remote access, more than half the balance in 24 h, new payee) and holds the payment 24 h with a bank call-back.
  On 120 synthetic scenarios we wrote (`evaluate_human.py`; design results): 50/60 coached frauds held or stepped up.
  Open: a victim coached earlier, with no live signal, paying a small amount under the cap is paid (10/10). Cost: 10/60
  legitimate payments held (a large first payment to a dealer who is on the phone).
* **A confirmed STEP-UP is held, not paid** (`release_policy()`: 4 h for a new payee, 1 h otherwise, cancel link to the
  registered contact). In the red team, the 10 attacks a customer who approves everything lets through are all held;
  whether a held victim cancels is not measured.
* **STEP-UP is only as good as the customer's answer.** The card (`confirmation_card()`) follows the best arm of a
  randomised in-app experiment (Akesson, Gathergood & Quispe-Torreblanca 2023: a risk-based warning plus a call to action
  cut falling for fraud by 81%, generic warnings by 18%), but our own human study is only pre-registered
  (`preregistrations/PREREGISTRATION_54_*`), not run.
* **A wrong product from a legitimate merchant inside the mandate** is not addressed (amounts to registered billers and
  saved payees are).
* **Host trust** is closed only if the bank's app signs each customer message (`sign_principal`, `verified_session`);
  without that, the gate must trust the host's record of which text the customer typed.
* **Models:** three families in the closed loop and two on the real payout server; gpt-oss-120b did not run on the real
  server (provider daily limit) and no model larger than these was tested live.
* **Synthetic data.** No real Aadhaar, VPA, account or person was used; no live UPI, bank or NPCI system was touched.
* **Registry data is held by the deployer.** Our tests use invented handles because NPCI restricts the real data to
  members: acquiring banks publish verified merchants to NPCI and every UPI app must download and store that list
  (NPCI Circular 18/2017, List VAE API; OC-95, 2020), and Bharat Connect biller IDs reach banks through their
  biller-data feeds. The bank or payment app that would run this gate already holds both; `biller_registry` is a plain
  entity-to-handle table they fill from that copy, with no code change.

## Lineage
Built on two research witnesses from the Aegis AI project: an authorization-provenance witness ("Who Said So?",
held-out benchmark of 383 cases) and a deed-provenance monitor ("Who Wrote the Target?", 209/210 SHADE-Arena sabotage
runs flagged). Closest prior work: A-VIP (arXiv 2609.11757) binds each cart line to the listing the user saw, for
Google's AP2; this applies the provenance idea to UPI's mandate model, adds inherited beneficiary provenance and a
registry check, and produces a liability receipt.
