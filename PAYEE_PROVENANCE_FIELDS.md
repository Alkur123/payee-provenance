# Draft: payee-provenance fields for agent-initiated payments

**Status:** proposal from Team Aegis AI (SAFL India Agentic AI Security Hackathon, 31 Oct 2026). Not an NPCI, RBI or ISO
document. Written so a standards body can adopt, change or reject it field by field.

## The gap these fields close
Every check on a payment rail today answers *is it you?* (PIN, OTP, device binding) or *is it them?* (payee-name
display, India's beneficiary name look-up, the UK's Confirmation of Payee, the EU's Verification of Payee). When an AI
agent pays, a third question decides whether the payment is the customer's: **who supplied this payee?** Agent mandates
(UPI Circle delegation, Reserve Pay, a planned Unified Agent Protocol) bound how much an agent may spend; nothing in them
records where the payee came from. These fields carry that answer with the payment, computed by the bank or PSP that
hosts the agent, from records only the customer and the bank can write.

## Fields (added to the agent payment request by the payer's PSP, after its gate has decided)

| field | type | meaning |
|---|---|---|
| `payeeProvenance.class` | enum `P` `K` `R` `D` `W` | P: a token in the customer's own signed message; K: a saved payee created by an authorised action; R: the registered handle of the biller a customer-named document claims; D: a customer-named document, unconfirmed by any registry; W: anything else |
| `payeeProvenance.sourceType` | enum `customer_message` `beneficiary_record` `biller_registry` `named_document` `external` | where the identifier was found |
| `payeeProvenance.sourceRef` | string (SHA-256, hex) | hash of the source text or record, so the source can be produced in a dispute without travelling with the payment |
| `gateDecision` | enum `ALLOW` `CONFIRMED_HOLD` | only these two reach the rail: a BLOCK never becomes a payment request, and a confirmation the customer declined never does either |
| `confirmation` | object, optional | `{id, approvedAt, holdUntil}` when the customer approved a step-up in the bank's app |
| `receiptRef` | object | `{seq, mac}` of the PSP's signed receipt for this decision |
| `mandateRef` | object | `{mandateId, version}` the agent acted under |
| `agentId` | string | the agent that proposed the payment |

A payee of class W never appears in a payment request. Class D appears only with a `confirmation`.

## JSON Schema (draft 2020-12)
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "AgentPayeeProvenance",
  "type": "object",
  "required": ["payeeProvenance", "gateDecision", "receiptRef", "mandateRef", "agentId"],
  "properties": {
    "payeeProvenance": {
      "type": "object",
      "required": ["class", "sourceType", "sourceRef"],
      "properties": {
        "class": {"enum": ["P", "K", "R", "D"]},
        "sourceType": {"enum": ["customer_message", "beneficiary_record", "biller_registry", "named_document"]},
        "sourceRef": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
      }
    },
    "gateDecision": {"enum": ["ALLOW", "CONFIRMED_HOLD"]},
    "confirmation": {
      "type": "object",
      "required": ["id", "approvedAt", "holdUntil"],
      "properties": {"id": {"type": "string"}, "approvedAt": {"type": "string", "format": "date-time"},
                     "holdUntil": {"type": "string", "format": "date-time"}}
    },
    "receiptRef": {"type": "object", "required": ["seq", "mac"],
                   "properties": {"seq": {"type": "integer", "minimum": 0}, "mac": {"type": "string", "pattern": "^[0-9a-f]{64}$"}}},
    "mandateRef": {"type": "object", "required": ["mandateId", "version"],
                   "properties": {"mandateId": {"type": "string"}, "version": {"type": "integer"}}},
    "agentId": {"type": "string"}
  },
  "allOf": [{"if": {"properties": {"payeeProvenance": {"properties": {"class": {"const": "D"}}}}},
             "then": {"required": ["confirmation"], "properties": {"gateDecision": {"const": "CONFIRMED_HOLD"}}}}]
}
```
Class `W` and sourceType `external` are deliberately absent from the schema: such a payee is refused before a request
exists.

## How each party uses the fields
* **Payer PSP / bank:** computes the fields (the reference implementation in this repository: `gate.py`, `bank_api.py`,
  `server.py`), refuses W, holds confirmed D, and keeps the signed receipt. Under RBI's directions applying from
  1 January 2027 the bank bears the burden of proof in a disputed fraudulent electronic banking transaction; the receipt
  records, at payment time, who supplied the payee.
* **Switch (NPCI):** can reject an agent payment request that lacks the fields, or that carries class D without a
  confirmation, without inspecting any content. Fraud monitoring can treat confirmed-D payments to new payees as a
  higher-risk segment.
* **Payee PSP:** unchanged.
* **Dispute desk / ombudsman:** reads class, source and confirmation from the receipt; `receipt.py` maps them to a
  plain-language account.

## Mapping to ISO 20022 (for SEPA, Faster Payments and other ISO 20022 rails)
ISO 20022 credit-transfer messages (for example `pain.001` from customer to bank and `pacs.008` between banks) carry an
optional `SupplementaryData` block (`SplmtryData`, with a place-and-name and a free envelope). The same object can travel
there unchanged; a market practice group would fix the place-and-name. Name-matching services already mandated (the UK's
Confirmation of Payee, the EU's Verification of Payee under Regulation (EU) 2024/886) are complementary: they confirm that
a name belongs to an account; these fields record who supplied the account.

## What this draft does not settle
Exact placement inside NPCI's message formats (for NPCI to decide); retention period of receipts; how a payee PSP may use
the fields; key management for the receipt MAC (the bank's existing HSM or key service).
