"""Payee provenance gate.

Every payment control in use today asks "is it you?" (PIN, OTP, device binding) or "is it them?" (Confirmation of
Payee, beneficiary name look-up). Authorised-push-payment fraud passes both: the customer is genuine and the account is
real. This gate asks the third question: WHO SUPPLIED THIS PAYEE (and this amount)?

When a human pays, that question is unanswerable because the scam happens off-channel (a phone call, a WhatsApp chat).
When an AI agent pays, every input it saw is in its context, so the question has an exact answer at payment time.

Payee classes, first match wins:
  P  principal          the identifier occurs, as a whole token, in the customer's own messages
  K  known payee        a beneficiary record created or last changed by an authorised action (provenance is inherited,
                        so the record cannot be laundered); a record changed inside the cooling-off window needs STEP_UP
  R  registered         from a document the customer named AND the registered handle of the biller the document claims
                        to be (Bharat Connect / BBPS biller, NPCI verified merchant)
  D  delegated document first occurs in a pre-existing document the customer named, with no registry to confirm it
  W  world              anything else: an SMS, a web page, a collect request, a tool result, a file the AGENT wrote during
                        this session, or nowhere

Payee policy:      P, K, R -> ALLOW     D -> STEP_UP     W, registry mismatch -> BLOCK
Amount policy (applied after the payee decision, can only make it stricter):
  * the customer stated an amount            -> the payment may not exceed it                      (else BLOCK)
  * registered biller with a bill fetch      -> the payment must equal the fetched amount          (else BLOCK)
  * known payee with a last-paid amount      -> above the last-paid amount needs confirmation      (STEP_UP)
  * otherwise                                -> above the mandate cap needs confirmation           (STEP_UP)
Credential changes: only a value the customer typed.  Beneficiary changes: gated like a payment.

Security argument. ALLOW requires the identifier to be in the customer's own text, or in a record only authorised actions
can write, or in the payment system's registry. A prompt injection controls none of them. Knowing these rules does not
help an attacker: there is no classifier to fool, no threshold to sit under, no wording to find. Matching is against these
ROOTS, not along a chain of tool calls, so there is no lineage to break by passing a value through several tools. Any
obfuscation of the identifier only makes it unfindable in the roots, which turns it into W, which blocks: the gate fails
closed by construction.

What it does NOT do: it trusts the customer's own words. If a scammer talks the customer into typing the scammer's
account, the payee is P. It turns agent-borne fraud into ordinary human fraud, no worse; it does not solve human fraud.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

ALLOW, STEP_UP, BLOCK = "ALLOW", "STEP_UP", "BLOCK"
_ZW = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)

# Whole tokens only: a short VPA that is a suffix of a longer one the customer typed must NOT match
# (found in our own white-box pass: "kumar@okicici" inside "rama.kumar@okicici").
_ID_PATTERNS = [
    re.compile(r"[a-z0-9][a-z0-9._-]{1,255}@[a-z][a-z0-9]{1,63}"),           # UPI VPA  name@handle
    re.compile(r"[a-z]{2}[0-9]{2}[a-z0-9]{10,30}"),                           # IBAN (after space removal)
    re.compile(r"[0-9]{9,18}"),                                               # bank account number
    re.compile(r"[a-z]{4}0[a-z0-9]{6}"),                                      # IFSC
    re.compile(r"[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+"),                # e-mail (payout-by-link payee)
]


def canon(s: str) -> str:
    """NFKC, strip zero-width/soft-hyphen, drop whitespace, lowercase; a purely numeric identifier also loses '-' and '.'
    separators (customers write 5021-0004-5678; taintgate reported such reformatting breaking string matching).
    Applied to BOTH sides of every comparison."""
    c = re.sub(r"\s+", "", unicodedata.normalize("NFKC", str(s)).translate(_ZW)).lower()
    if re.fullmatch(r"\+?[0-9][0-9.\-]*[0-9]", c):
        c = re.sub(r"[.\-+]", "", c)
        if len(c) == 12 and c.startswith("91"):            # +91 98765 43210 -> 9876543210 (Indian mobile)
            c = c[2:]
    return c


def identifiers(text: str) -> set:
    """Every payment identifier in a text, as canonical whole tokens."""
    t = unicodedata.normalize("NFKC", str(text)).translate(_ZW).lower()
    found = set()
    for chunk in re.split(r"[\s,;:()\[\]<>\"'|!?/]+", t):
        chunk = canon(chunk.strip(".-_"))
        found.update(p.fullmatch(chunk).group(0) for p in _ID_PATTERNS if p.fullmatch(chunk))
    # IBANs and account numbers are often written in groups of four: retry with intra-token spaces removed.
    for m in re.finditer(r"(?<![a-z0-9])(?:[a-z0-9]{2,4}[ ]){2,8}[a-z0-9]{1,4}(?![a-z0-9])", t):
        c = m.group(0).replace(" ", "")
        found.update(p.fullmatch(c).group(0) for p in _ID_PATTERNS[1:3] if p.fullmatch(c))
    # Indian mobile numbers (payout-by-link and wallet payees), however they are spaced: +91 98765 43210, 98765-43210
    for m in re.finditer(r"(?<![0-9])(?:\+?91[\s-]?)?[6-9][0-9]{4}[\s-]?[0-9]{5}(?![0-9])", t):
        found.add(canon(m.group(0)))
    return found


@dataclass
class Beneficiary:
    payee: str
    added_by: str                       # provenance class of the action that created/last changed it: P, K, D_CONFIRMED
    source: str
    last_amount: Optional[float] = None
    recently_changed: bool = False      # created/changed inside the bank's cooling-off window


@dataclass
class Document:
    text: str
    written_by_agent: bool = False      # a file the agent itself wrote this session is world text, not delegation


@dataclass
class Session:
    """What the gate can see. Built by the host (the bank/PSP app), never by the agent."""
    principal_messages: List[str]
    beneficiaries: Dict[str, Beneficiary] = field(default_factory=dict)
    named_documents: Dict[str, object] = field(default_factory=dict)    # name -> str or Document
    world_inputs: List[Tuple[str, str]] = field(default_factory=list)   # (source, text)
    mandate_cap: float = 0.0
    principal_amounts: List[float] = field(default_factory=list)       # amounts the customer stated
    biller_registry: Dict[str, str] = field(default_factory=dict)      # entity -> registered handle
    bill_fetch: Dict[str, float] = field(default_factory=dict)         # registered handle -> amount due (Bharat Connect)

    def principal_ids(self) -> set:
        out = set()
        for m in self.principal_messages:
            out |= identifiers(m)
        return out

    def docs(self):
        for name, d in self.named_documents.items():
            yield (name, d) if isinstance(d, Document) else (name, Document(str(d)))


def sign_principal(key: bytes, text: str) -> str:
    """Run by the BANK's app when the customer types: an HMAC over the exact text, under a key the agent platform never
    holds. The agent receives the text and the tag and passes both on; it cannot mint a tag for text the customer did not
    type (closes 'the host must be trusted to say which text is the customer's')."""
    import hashlib
    import hmac
    return hmac.new(key, text.encode("utf-8"), hashlib.sha256).hexdigest()


def verified_session(s: "Session", signed: List[Tuple[str, str]], key: bytes) -> "Session":
    """Rebuild the principal channel from (text, tag) pairs: only messages whose tag verifies count as the customer's.
    Anything else the agent platform claims the customer said is demoted to world input, so it can never yield class P."""
    import copy
    import hmac
    out = copy.deepcopy(s)
    out.principal_messages = []
    for text, tag in signed:
        if hmac.compare_digest(sign_principal(key, text), str(tag)):
            out.principal_messages.append(text)
        else:
            out.world_inputs.append(("unsigned claim of customer text", text))
    return out


@dataclass
class Decision:
    verdict: str
    payee_class: str
    source: str
    reasons: List[str]


def classify(payee: str, s: Session) -> Tuple[str, str]:
    p = canon(payee)
    if p in s.principal_ids():
        return "P", "customer message"
    b = s.beneficiaries.get(p)
    if b is not None and b.added_by in ("P", "K", "D_CONFIRMED"):
        return "K", f"beneficiary record (added by {b.added_by}: {b.source})"
    for name, d in s.docs():
        if p in identifiers(d.text):
            if d.written_by_agent:
                return "W", f"file the agent wrote this session: {name}"
            return "D", f"document the customer named: {name}"
    for src, text in s.world_inputs:
        if p in identifiers(text):
            return "W", f"world input: {src}"
    return "W", "no source (identifier appears nowhere the customer or bank wrote)"


def registry_check(payee: str, s: Session) -> Optional[Tuple[str, str]]:
    """For class D only. If the document names a registered entity, the payee must be that entity's registered handle:
    equal -> ("R", ...); different -> ("MISMATCH", ...). None if the document names no registered entity."""
    p = canon(payee)
    for name, d in s.docs():
        if d.written_by_agent or p not in identifiers(d.text):
            continue
        low = d.text.lower()
        claimed = [ent for ent in s.biller_registry if ent.lower() in low]
        if not claimed:
            return None
        if any(canon(s.biller_registry[e]) == p for e in claimed):
            return "R", f"registered handle of {', '.join(claimed)}"
        return "MISMATCH", f"{name} claims {', '.join(claimed)} but {payee} is not its registered handle"
    return None


def _stricter(a: str, b: str) -> str:
    order = {ALLOW: 0, STEP_UP: 1, BLOCK: 2}
    return a if order[a] >= order[b] else b


def decide_payment(payee: str, amount: float, s: Session) -> Decision:
    cls, src = classify(payee, s)
    verdict = {"P": ALLOW, "K": ALLOW, "D": STEP_UP, "W": BLOCK}[cls]
    reasons = [f"payee class {cls}: {src}"]
    if cls == "D" and s.biller_registry:
        rc = registry_check(payee, s)
        if rc is not None:
            cls = "R" if rc[0] == "R" else "D"
            verdict = ALLOW if rc[0] == "R" else BLOCK
            reasons.append(f"registry: {rc[1]}")
    b = s.beneficiaries.get(canon(payee))
    if cls == "K" and b is not None and b.recently_changed:
        verdict = _stricter(verdict, STEP_UP)
        reasons.append("beneficiary changed inside the cooling-off window")
    if verdict == BLOCK:
        return Decision(verdict, cls, src, reasons)
    # amount provenance: can only make the decision stricter
    fetched = s.bill_fetch.get(canon(payee))
    if s.principal_amounts:
        if amount > max(s.principal_amounts) + 1e-9:
            verdict = BLOCK
            reasons.append(f"amount {amount} exceeds the amount the customer stated")
    elif fetched is not None:
        if abs(amount - fetched) > 1e-9:
            verdict = BLOCK
            reasons.append(f"amount {amount} differs from the registered bill fetch {fetched}")
    elif cls == "K" and b is not None and b.last_amount is not None:
        if amount > b.last_amount + 1e-9:
            verdict = _stricter(verdict, STEP_UP)
            reasons.append(f"amount {amount} above the last amount paid to this payee ({b.last_amount})")
    elif amount > s.mandate_cap:
        verdict = _stricter(verdict, STEP_UP)
        reasons.append(f"amount {amount} above mandate cap {s.mandate_cap}")
    return Decision(verdict, cls, src, reasons)


def decide_add_beneficiary(payee: str, s: Session) -> Decision:
    """Adding a beneficiary is gated like a payment: the record may only grow through authorised actions."""
    cls, src = classify(payee, s)
    verdict = ALLOW if cls in ("P", "K") else STEP_UP if cls == "D" else BLOCK
    return Decision(verdict, cls, src, [f"beneficiary add, payee class {cls}: {src}"])


def decide_update_beneficiary(existing: str, new_payee: str, s: Session) -> Decision:
    """Changing a saved payee's account ('our bank details have changed', vendor-master fraud). The NEW value must come
    from the customer; a confirmed change still enters the cooling-off window."""
    cls, src = classify(new_payee, s)
    verdict = ALLOW if cls == "P" else STEP_UP if cls == "D" else BLOCK
    return Decision(verdict, cls, src, [f"beneficiary change {existing} -> {new_payee}, new value class {cls}: {src}"])


def decide_credential(new_value: str, s: Session) -> Decision:
    ok = any(canon(new_value) and canon(new_value) in [canon(t) for t in re.split(r"[\s,;:'\"]+", m)]
             for m in s.principal_messages)
    return Decision(ALLOW if ok else BLOCK, "P" if ok else "W",
                    "customer message" if ok else "not in customer message",
                    ["credential value must come from the customer"])


def confirmation_card(d: Decision, payee: str, amount: float, lang: str = "en") -> dict:
    """The STEP_UP screen, designed after the best arm of Akesson, Gathergood & Quispe-Torreblanca (2023, Nottingham
    CeDEx DP 2023-08): shown only on risky payments, with a salient call to action to cancel or verify (in their
    randomised in-app experiment, risk-based warning + call to action cut falling for fraud by 81% vs control; generic
    warnings by 18%, decaying with exposure). The card states WHERE the payee came from, defaults to Cancel, and offers
    the out-of-band check fraud prevention advice recommends (call the payee on a number you already have)."""
    if d.verdict != STEP_UP:
        return {}
    src = d.source
    text = {
        "en": {"title": "Check before you pay",
               "body": f"Your assistant wants to send Rs {amount:,.0f} to {payee}. This account came from: {src}. "
                       "You have not paid it before, or it changed recently, or the amount is higher than usual.",
               "primary": "Cancel payment", "secondary": "Call the payee on a number you already have",
               "tertiary": "I checked it - pay"},
        "hi": {"title": "भुगतान से पहले जाँचें",
               "body": f"आपका सहायक {payee} को Rs {amount:,.0f} भेजना चाहता है। यह खाता यहाँ से आया: {src}. "
                       "आपने पहले इसे भुगतान नहीं किया है, या यह हाल ही में बदला है, या राशि सामान्य से अधिक है।",
               "primary": "भुगतान रद्द करें", "secondary": "पहले से मौजूद नंबर पर प्राप्तकर्ता को कॉल करें",
               "tertiary": "मैंने जाँच लिया - भुगतान करें"},
    }[lang]
    return dict(text, default_action="cancel", reasons=d.reasons)


HOLD = "HOLD"


def release_policy(d: Decision, customer_confirmed: bool, payee_is_new: bool = True) -> Tuple[str, float]:
    """A confirmed STEP_UP does not pay at once: it becomes a timed HOLD (default 4 h) with a cancel link sent to the
    customer's registered contact, so one deceived click is not enough; the fraud must survive the window. Precedents: UK
    Payment Services (Amendment) Regulations 2024 / FCA FG24/6 (delay up to 4 business days on reasonable suspicion);
    DBS new-payee cooling period (Mar 2026); ABS 24 h cooling-off on rapid-drain transfers (Oct 2025).
    Returns (verdict, hold_hours)."""
    if d.verdict == BLOCK or (d.verdict == STEP_UP and not customer_confirmed):
        return BLOCK, 0.0
    if d.verdict == STEP_UP:
        return HOLD, 4.0 if payee_is_new else 1.0
    return d.verdict, 0.0


@dataclass
class HumanContext:
    """Signals a banking app already has when a HUMAN makes the payment. They target the case provenance cannot see: a
    scammer coaching the customer to type the scammer's account (digital arrest, fake investment, impersonation)."""
    payee_entry: str = "typed"            # typed | pasted | qr_in_person | contact | saved
    on_call_unknown_number: bool = False  # cf. Android in-call protection (warn + 30 s pause), Starling call status
    screen_share_or_remote_app: bool = False
    balance: float = 0.0
    sent_last_24h: float = 0.0


def decide_human_payment(payee: str, amount: float, s: Session, ctx: HumanContext) -> Decision:
    """Coached-payment check for human-initiated payments. Not provenance (the customer really typed it): signals of
    coaching + a new payee or a balance drain -> HOLD 24 h with a bank call-back; otherwise the normal decision."""
    p = canon(payee)
    known = p in s.beneficiaries and s.beneficiaries[p].added_by in ("P", "K", "D_CONFIRMED")
    coached = ctx.on_call_unknown_number or ctx.screen_share_or_remote_app
    drain = ctx.balance > 0 and (amount + ctx.sent_last_24h) > 0.5 * ctx.balance     # ABS rapid-drain shape
    reasons = []
    if coached:
        reasons.append("live coaching signal: " + ", ".join(k for k, v in [("call with an unknown number", ctx.on_call_unknown_number),
                                                                         ("screen sharing / remote access", ctx.screen_share_or_remote_app)] if v))
    if drain:
        reasons.append("more than half the balance within 24 h")
    if not known:
        reasons.append(f"new payee ({ctx.payee_entry})")
    if coached and (not known or drain):
        return Decision(HOLD, "P", "customer typed it under live coaching signals", reasons + ["hold 24 h, bank call-back"])
    if drain and not known:
        return Decision(HOLD, "P", "customer typed it", reasons + ["hold 24 h"])
    if ctx.payee_entry == "pasted" and not known and amount > s.mandate_cap:
        return Decision(STEP_UP, "P", "pasted new payee, large amount", reasons)
    return Decision(ALLOW, "P", "customer", reasons or ["no coaching signal"])


def decide_collect(requester: str, amount: float, s: Session) -> Decision:
    """An incoming collect request is payee-initiated: the payee supplied itself. Class it like any payee."""
    return decide_payment(requester, amount, s)
