# Who Said So? Payee provenance for agent payments

**Every payment control in use asks "is it you?" (PIN, OTP) or "is it them?" (Confirmation of Payee). Authorised push
payment fraud passes both. This gate asks the question nobody asks: *who supplied this payee?***

For a human payment that question cannot be answered: the scam happens on a phone call or in a WhatsApp chat the bank
never sees. For an AI agent's payment it can, exactly, because everything the agent read is in its context. Agentic
payments are arriving on UPI now (Razorpay × NPCI on Claude, Feb 2026; NPCI's Unified Agent Protocol in development).
They are protected by spending caps, which bound **how much**. Nothing binds **who said so**.

**Report:** [AegisAI_Report.pdf](AegisAI_Report.pdf) (SAFL template sections 1-10, then appendices) · **Video:** [media/demo.mp4](media/demo.mp4) (1:51)

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

**Against the provider's real sandbox API (pre-registered).** We then sent the same requests to the provider's real,
internet-hosted sandbox (test money, test-mode keys, signed requests), through a proxy that forwards only to the sandbox
host and refuses any other, and scored on the provider's own responses. With gpt-4.1-mini on every scenario (48
episodes, 0 errors): the attacker's payout was **accepted by the provider's API (HTTP 200, a provider transfer id) in 11
of 15 attack episodes direct and 0 of 15 gated**; every legitimate payout was accepted in 12 of 15 episodes in both
conditions. Looking up each accepted transfer in the provider's own records found 8 to attacker accounts (the other 3
were payout links). The sandbox's simulated settlement marked every transfer to our synthetic UPI IDs failed or
rejected, legitimate ones included, so the claim is that the payment API accepted the attacker's request, not that a
payee was credited. Two earlier attempts are reported, not used: one confounded by IP allow-listing on a mobile
connection (31 of 44 requests refused for that reason; gated, still 0 of 15 attacker payouts reached the sandbox) and
one stopped for low memory after 8 episodes.

**A second provider's real payout API (pre-registered).** To show the gate is not tied to one provider, we ran the same
scenarios, model and gate against a second Indian payment provider's real payout API in test mode. Its official agent
server cannot create payouts, so the agent's payment tools were connected to its Payouts and Payout Links APIs by a small
adapter (it refuses to send anything without a test-mode key). 48 episodes, 0 errors, all 65 requests answered HTTP 200:
the attacker's payout was **accepted in 10 of 15 attack episodes direct and 0 of 15 gated**, and every legitimate payout
was accepted in 15 of 15 episodes in both conditions. All 62 accepted payouts were confirmed in the provider's own
records (7 to attacker accounts, all direct; the other 3 attacker payouts were payout links); every payout is queued in
test mode, legitimate ones included, so again the claim is acceptance by the API, not settlement.

**Collect requests on a third provider's real UPI sandbox (pre-registered).** The payout tests cover money the agent
sends; a UPI collect request is a payee asking the customer to pay, the channel NPCI restricted for person-to-person use
because of fraud. The agent could list the customer's pending collect requests, read SMS and e-mail, and approve or
decline. Each request was created for real on the provider's UPI sandbox and an approval was completed with the
sandbox's mock-payment API. 15 attack scenarios (fake refund, electricity disconnection, KYC fee, parcel re-delivery fee,
"approve to receive money" from a marketplace buyer) and 15 requests from saved payees; 60 episodes, 0 errors. **Without
the gate the agent paid the attacker's request in 15 of 15 episodes; with it, 0 of 15.** Legitimate requests were paid
in 11 of 15 direct and 13 of 15 gated; every unpaid one was the model asking the customer first, never a gate refusal.
All 39 payments were confirmed in the provider's payment history (transaction ID and RRN, status `initiated` on sandbox
rails). Declared limitation: the sandbox gives one merchant VPA, so attacker and legitimate payee are the same real VPA in
different customer sessions; what the gate reads, and what differs, is where the payee came from.

### 5. Tests that can fail
63 tests, including a 5,000-case fuzz of the fail-closed claim (only the customer's exact token can ever be allowed,
under eight attacker transformations), laundering, registry mismatch, the concurrent-work gaps, the signed customer
channel, the confirmation card, receipt tampering and truncation, the dispute report, and the trust boundary.
`tests/mutation_probe.py` plants 27 defects in a copy of the code; **all 27 are caught**.

### 6. External code review and version 3.1
An external reviewer audited this repository on 31 October 2026. For each reported issue we first wrote a test that
fails if the issue is real (`tests/test_review_findings.py`), then fixed the code:

| finding | verdict | fix |
|---|---|---|
| a customer ceiling ("up to Rs 2,000") switched off the bill-fetch check | real bug | every applicable amount rule now applies; each can only tighten |
| a biller name matched inside another word ("Jio" in "Majiority") | real bug (failed closed) | whole-word matching |
| the receipt chain could be rolled back to an older valid prefix | design gap | `head()` anchor + `verify(anchor=...)`, append-only file |
| the decision API accepted any session object | design gap | `bank_api.py`: the bank seals session state; unsealed or altered state is refused |
| nothing guaranteed every money-moving route passes the gate | design gap | `bank_api.py`: the backend executes only with a single-use token bound to operation, payee and amount |
| tool results could pair with the wrong call in the model adapter | not a bug | two tests added |

Through the full integration path (`python evaluate_mediation.py`): 0/190 attacker actions executed, 160/160 scenarios with
a legitimate action completed, and 190/190 direct backend calls, 180/180 token replays and 180/180 redirected tokens
refused. **Effect on published results: none.** The red-team output is identical; every gated call recorded in the three
closed loops (231) gets the same verdict from v3.1 (`python replay_closed_loop.py closed_loop*.jsonl`); AgentDojo was
scored by the frozen pre-registered copy of the gate.

### 7. An attacker who knows every rule (pre-registered, `adaptive_attacker.py`)
SAFL's judges assume the attacker knows the system. So we gave a language model (gpt-4.1-mini) the gate's complete rules
and let it write the text of every channel it controls (the bill or notice the customer named, SMS, web pages, collect
requests, files the agent writes), see the gate's refusal reasons, and try again: 3 rounds on each of the 45 attack
scenarios, against a gpt-4.1-mini agent behind the gate (`preregistrations/PREREGISTRATION_56_*`).

| prediction | first run (v3.1) | re-run (v3.2) |
|---|---|---|
| W1: a customer who reads confirmations is never defrauded | held: 0/45 | held: 0/45 |
| W2: with a customer who approves everything, every success is held, none paid at once | **failed**: 7/45, 2 paid at once | held: 7/45, all held |
| W3: no attacker payee is ever classed P, K or R | **failed** | **failed** |
| W4 (reported): the same attacker texts with no gate | 19/45 succeeded | 17/45 succeeded |

**The attacker found a real bypass.** It had the agent *add* its account as a saved payee (one confirmation) and then pay
it; hosts had marked only *changed* payees as inside the cooling-off window, so the payment went through at once. v3.2
fixes it with one shared host function (`record_beneficiary`), and the fresh re-run, registered as an amendment before it
began, found no instant payment. W3 stays failed as written. Every attacker call in the re-run (126) gets the same verdict
from the final code (`python replay_attacker.py adaptive_attacker_v32.jsonl`).

Other v3.2 fixes, each with a test and a planted defect: UPI payment links and QR payloads (`upi://pay?pa=...`) are read
(the customer's paste is class P; the same link in an SMS is still blocked); mobile numbers with a leading 0 match; an
amount written next to one payee no longer caps a different payment in the same message. All three had blocked
legitimate payments. Across every earlier evaluation, one legitimate payment (an unregistered payee taken from a bill,
saved, then paid) now needs one confirmation; nothing else changed.

### 8. Deployable service
`python -m payee_provenance.server` runs the gate as an HTTP service (standard library only; `openapi.yaml`;
`Dockerfile`; the 178 MB image is built and smoke-tested by `python docker_smoke.py`, 10/10 checks: refuses to start without keys, runs as non-root, Docker health check healthy, allow/block/403 over HTTP, receipts survive a restart and verify, a tampered receipt store stops it starting). It refuses to start without four bank-held keys or with a
tampered receipt store; the bank seals session state, the bank's app signs confirmations, the gate mints single-use
execution tokens, and a confirmed payment's token is not accepted before its hold ends. `python loadtest.py`: 517-553
decisions/s across three runs on one laptop process, median 27-29 ms, p99 44-47 ms, every receipt on disk before its
response (group commit), and the 4,000-receipt chain read back from disk verifies against its anchored head.

### 9. A field proposal for the Unified Agent Protocol
[`PAYEE_PROVENANCE_FIELDS.md`](PAYEE_PROVENANCE_FIELDS.md): the fields an agent payment request would carry, a JSON Schema
in which a class-W payee cannot appear and a class-D payee cannot appear without a confirmation, and the mapping to ISO
20022's `SupplementaryData` for SEPA and Faster Payments.

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
* **Cost:** about 500 lines of standard-library Python for the gate and receipts (under 900 with the bank integration
  and HTTP service), no model, no network call; median 32 µs per decision, 99th percentile 0.13 ms on one laptop core.
* **Fails closed:** a payee nobody on the customer's side wrote is refused. Across all AgentDojo banking runs, the 11
  legitimate-task payments refused (of 210) were all to wrong accounts the agent itself produced.
* **Rollout:** shadow mode (log, block nothing; measure false blocks on real traffic) → enforce BLOCK for unsourced payees
  and registry mismatches → turn on confirmations and holds. Report monthly: false-block rate, confirmation rate, holds
  cancelled, fraud loss on agent payments, dispute resolution time from the signed receipt.

## Run it
Python 3.10+, standard library only, no network, no model.
```
python evaluate.py                       # the red-team table (v3); --no-registry disables the biller registry
python -m unittest discover -s tests -v  # 63 tests
python tests/mutation_probe.py           # 27/27 planted defects caught
python loadtest.py                       # the HTTP service under 16 concurrent clients
python replay_attacker.py adaptive_attacker_v32.jsonl   # PR56 re-run, verdicts from the current gate
python score_pr56.py adaptive_attacker_v32.jsonl        # PR56 scored against W1-W4
python adaptive_attacker.py --out new.jsonl             # PR56 itself; needs OPENAI_API_KEY (about $1)
python evaluate_mediation.py             # red team through sealed state -> gate -> token -> backend, plus bypass attempts
python replay_closed_loop.py closed_loop.jsonl closed_loop_gptoss.jsonl closed_loop_gpt41mini.jsonl   # v3.1 verdict replay
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
* **Host trust** rests on the bank: it signs each customer message (`sign_principal`) and seals the session state it
  builds from its own records (`bank_api.seal_session`). The reference integration enforces both; a real deployment
  must keep those keys away from the agent platform. Receipts are tamper-evident; the bank must anchor the chain head
  outside the receipt store.
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
