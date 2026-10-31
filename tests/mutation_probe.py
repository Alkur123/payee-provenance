"""Non-vacuity check: plant each defect in a copy of the package and confirm the test suite fails on it.
    python tests/mutation_probe.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MUTANTS = {
    "substring match instead of whole token": ("gate.py", "if p in s.principal_ids():",
                                               "if any(p in x for x in s.principal_ids()) or p in canon(' '.join(s.principal_messages)):"),
    "beneficiary provenance ignored": ("gate.py", 'if b is not None and b.added_by in ("P", "K", "D_CONFIRMED"):',
                                       "if b is not None:"),
    "no NFKC / zero-width canonicalisation": ("gate.py", 'unicodedata.normalize("NFKC", str(s)).translate(_ZW)', "str(s)"),
    "registry mismatch allowed": ("gate.py", 'verdict = ALLOW if rc[0] == "R" else BLOCK', "verdict = ALLOW"),
    "receipt MAC not checked": ("receipt.py", "if not hmac.compare_digest(self._mac(body), rec[\"mac\"]):", "if False:"),
    "world payee gets step-up not block": ("gate.py", '"D": STEP_UP, "W": BLOCK}[cls]', '"D": STEP_UP, "W": STEP_UP}[cls]'),
    "agent-written file treated as delegation": ("gate.py", "            if d.written_by_agent:\n                return \"W\"",
                                                 "            if False:\n                return \"W\""),
    "bill fetch ignored": ("gate.py", "if fetched is not None and abs(amount - fetched) > 1e-9:", "if False:"),
    "last-paid amount ignored": ("gate.py", "and amount > b.last_amount + 1e-9):", "and False):"),
    # re-plant each bug the 31 Oct external review found (v3.1 fixes)
    "customer ceiling switches off bill fetch": ("gate.py", "if fetched is not None and abs(amount - fetched) > 1e-9:",
                                                 "if not stated and fetched is not None and abs(amount - fetched) > 1e-9:"),
    "registry claim by substring": ("gate.py", 'if re.search(r"(?<![0-9a-z])" + re.escape(ent.lower()) + r"(?![0-9a-z])", d.text.lower())]',
                                    "if ent.lower() in d.text.lower()]"),
    "receipt anchor ignored": ("receipt.py", 'if seq >= 0 and (seq >= len(self.entries) or self.entries[seq]["mac"] != anchor.get("mac")):',
                               "if False:"),
    "beneficiary change not gated": ("gate.py", 'verdict = ALLOW if cls == "P" else STEP_UP if cls == "D" else BLOCK\n    return Decision(verdict, cls, src, [f"beneficiary change',
                                     'verdict = ALLOW\n    return Decision(verdict, cls, src, [f"beneficiary change'),
    "cooling-off ignored": ("gate.py", "if cls == \"K\" and b is not None and b.recently_changed and not registered:", "if False:"),
    "principal signature not checked": ("gate.py", "        if hmac.compare_digest(sign_principal(key, text), str(tag)):",
                                        "        if True:"),
    "confirmed step-up pays at once": ("gate.py", "        return HOLD, 4.0 if payee_is_new else 1.0", "        return ALLOW, 0.0"),
    "coaching signal ignored": ("gate.py", "    if coached and (not known or drain):", "    if False:"),
    "no digit-separator canonicalisation": ("gate.py", '    if re.fullmatch(r"\\+?[0-9][0-9.\\-]*[0-9]", c):', "    if False:"),
    # found by the adaptive white-box attacker (PR56, v3.2)
    "added payee skips cooling-off": ("gate.py", '"added or changed in this session",\n                    recently_changed=True)',
                                      '"added or changed in this session",\n                    recently_changed=False)'),
    "stated amounts not bound to a payee": ("gate.py", "    stated = stated_amounts_for(payee, s)\n",
                                            "    stated = list(s.principal_amounts)\n"),
    "bound amount ignored for its own payee": ("gate.py", "    if p in bound:\n        return sorted(bound[p] | unbound)",
                                               "    if p in bound:\n        return sorted(unbound)"),
    # Indian identifier formats found by our own probe (v3.1)
    "UPI links not parsed": ("gate.py", "            if _ID_PATTERNS[0].fullmatch(c):\n                found.add(c)",
                             "            if False:\n                found.add(c)"),
    "trunk-zero mobile not canonicalised": ("gate.py", 'elif len(c) == 11 and c[0] == "0" and c[1] in "6789":', "elif False:"),
    # trust boundary and complete mediation (bank_api.py, v3.1)
    "session seal not checked": ("bank_api.py", '    if not hmac.compare_digest(hmac.new(bank_key, blob, hashlib.sha256).hexdigest(), str(seal)):',
                                 "    if False:"),
    "backend runs without a token": ("bank_api.py", '        if not token or "nonce" not in token or "tag" not in token:\n            raise Refused',
                                     '        if False:\n            raise Refused'),
    "token not bound to payee and amount": ("bank_api.py", '        if not hmac.compare_digest(hmac.new(self._key, body, hashlib.sha256).hexdigest(), str(token["tag"])):',
                                            "        if False:"),
    "token replay allowed": ("bank_api.py", '        if token["nonce"] in self._spent:', "        if False:"),
}


def main():
    killed = 0
    for name, (fname, old, new) in MUTANTS.items():
        d = tempfile.mkdtemp()
        shutil.copytree(ROOT, os.path.join(d, "pp"), ignore=shutil.ignore_patterns("__pycache__", "*.json"))
        path = os.path.join(d, "pp", "payee_provenance", fname)
        src = open(path, encoding="utf-8").read()
        assert src.count(old) == 1, f"mutant anchor not unique/absent: {name}"
        open(path, "w", encoding="utf-8").write(src.replace(old, new))
        r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"], cwd=os.path.join(d, "pp"),
                           capture_output=True, text=True)
        dead = r.returncode != 0
        killed += dead
        print(f"{'KILLED' if dead else 'SURVIVED':8s}  {name}")
        shutil.rmtree(d, ignore_errors=True)
    base = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"], cwd=ROOT, capture_output=True)
    print(f"\nunmutated suite passes: {base.returncode == 0};  mutants killed {killed}/{len(MUTANTS)}")


if __name__ == "__main__":
    main()
