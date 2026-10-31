"""Tests written from an external code review (31 Oct 2026), before any fix: each one fails if the reported bug is real."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from payee_provenance.gate import ALLOW, BLOCK, STEP_UP, Session, decide_payment  # noqa: E402
from payee_provenance.receipt import ReceiptChain  # noqa: E402

BESCOM = "bescom.billdesk@hdfcbank"


def bill_session(principal, amounts, fetched=1840.0, cap=10**9):
    s = Session(principal_messages=[principal], mandate_cap=cap, principal_amounts=amounts)
    s.named_documents["bill.pdf"] = f"BESCOM electricity bill. Amount due Rs 1,840. Pay to {BESCOM}"
    s.biller_registry["BESCOM"] = BESCOM
    s.bill_fetch[BESCOM] = fetched
    return s


class AmountConstraintsAreCumulative(unittest.TestCase):
    """Finding 2: a customer ceiling must not switch off the authoritative bill-fetch check."""

    def test_bill_fetch_still_applies_under_a_customer_ceiling(self):
        s = bill_session("pay my electricity bill in bill.pdf, up to Rs 2000", [2000.0])
        self.assertNotEqual(decide_payment(BESCOM, 1950, s).verdict, ALLOW)

    def test_exact_bill_amount_under_ceiling_is_allowed(self):
        s = bill_session("pay my electricity bill in bill.pdf, up to Rs 2000", [2000.0])
        self.assertEqual(decide_payment(BESCOM, 1840, s).verdict, ALLOW)

    def test_mandate_cap_applies_under_a_customer_ceiling(self):
        s = Session(principal_messages=["pay ravi@okaxis for the repair, up to Rs 9000"], mandate_cap=5000,
                    principal_amounts=[9000.0])
        self.assertEqual(decide_payment("ravi@okaxis", 8000, s).verdict, STEP_UP)

    def test_customer_exact_amount_is_its_own_authority(self):
        s = Session(principal_messages=["send Rs 9000 to ravi@okaxis"], mandate_cap=5000, principal_amounts=[9000.0])
        self.assertEqual(decide_payment("ravi@okaxis", 9000, s).verdict, ALLOW)


class RegistryMatchingUsesWholeWords(unittest.TestCase):
    """Finding 4: a registered entity name inside an unrelated word must not count as a claim to be that biller."""

    def test_entity_name_inside_another_word_is_not_a_claim(self):
        s = Session(principal_messages=["pay the invoice in inv.pdf"], mandate_cap=10**9)
        s.named_documents["inv.pdf"] = "Majiority Traders, invoice 17. Pay to majiority@okicici"
        s.biller_registry["Jio"] = "jio.recharge@icici"
        self.assertEqual(decide_payment("majiority@okicici", 500, s).verdict, STEP_UP)

    def test_real_claim_with_wrong_handle_still_blocks(self):
        s = Session(principal_messages=["pay the bill in jio.pdf"], mandate_cap=10**9)
        s.named_documents["jio.pdf"] = "Jio postpaid bill. Pay to jio-payments@ybl"
        s.biller_registry["Jio"] = "jio.recharge@icici"
        self.assertEqual(decide_payment("jio-payments@ybl", 500, s).verdict, BLOCK)


class ReceiptTruncationIsDetected(unittest.TestCase):
    """Finding 3: replacing the store with an older valid prefix must be detectable against an external anchor."""

    def test_truncated_chain_fails_against_anchor(self):
        c = ReceiptChain(b"k" * 32)
        for i in range(5):
            c.append(agent_id="a", mandate_id="m", mandate_version=1, instruction="x", payee=f"p{i}@ybl", amount=1,
                     payee_class="P", source="s", verdict="ALLOW", ts=0)
        anchor = c.head()
        c.entries = c.entries[:3]
        self.assertTrue(c.verify())                      # the prefix is internally consistent...
        self.assertFalse(c.verify(anchor=anchor))        # ...but not against the anchored head


class TransportPairsEveryToolCall(unittest.TestCase):
    """Review note: tool results must pair with the right call when one turn makes several calls."""

    def test_two_calls_in_one_turn(self):
        from payee_provenance.transport import to_openai
        msgs = [{"role": "user", "content": "x"},
                {"role": "assistant", "content": "", "tool_calls": [
                    {"id": "c1", "function": {"name": "read_document", "arguments": {"name": "a"}}},
                    {"id": "c2", "function": {"name": "list_payees", "arguments": {}}}]},
                {"role": "tool", "content": "A"}, {"role": "tool", "content": "B"}]
        out = to_openai(msgs)
        self.assertEqual([m.get("tool_call_id") for m in out if m["role"] == "tool"], ["c1", "c2"])

    def test_missing_result_does_not_shift_later_pairs(self):
        from payee_provenance.transport import to_openai
        msgs = [{"role": "assistant", "content": "", "tool_calls": [
                    {"id": "c1", "function": {"name": "f", "arguments": "{}"}}]},
                {"role": "assistant", "content": "", "tool_calls": [
                    {"id": "c2", "function": {"name": "g", "arguments": "{}"}}]},
                {"role": "tool", "content": "B"}]
        out = to_openai(msgs)
        self.assertEqual([m.get("tool_call_id") for m in out if m["role"] == "tool"], ["c2"])


if __name__ == "__main__":
    unittest.main()
