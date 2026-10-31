"""Assemble the template-structured report from the long report's vetted blocks plus the rewritten body."""
import re

SP = r"C:\Users\jaswa\AppData\Local\Temp\claude\C--Users-jaswa-Downloads-vision--v3-chakravyuha\87b677c5-9544-4948-bf66-acf7715c268f\scratchpad\\"
RD = r"C:\Users\jaswa\Downloads\vision-_v3_chakravyuha\contrib\payee-provenance\report\\"
B = "\\"
L = open(RD + "report_long_13pp.tex", encoding="utf-8").read()
body = "".join(open(SP + f, encoding="utf-8").read() for f in ("body_head.tex", "body_mid.tex", "body_tail.tex"))


def between(a, b):
    i = L.index(a)
    return L[i + len(a):L.index(b, i + len(a))]


def wsre(text):
    return re.compile(r"\s+".join(re.escape(w) for w in text.split()))


def sub_once(s, old, new):
    rx = wsre(old)
    hits = rx.findall(s)
    assert len(hits) == 1, (len(hits), old[:60])
    return rx.sub(lambda m: new, s, count=1)


pre = L[:L.index(B + "begin{document}")]
i = L.index(B + "begin{figure}[t]"); j = L.index(B + "end{figure}", i) + len(B + "end{figure}"); figR = L[i:j]
k = L.index(B + "label{fig:flow}"); i2 = L.rindex(B + "begin{figure}[t]", 0, k)
j2 = L.index(B + "end{figure}", k) + len(B + "end{figure}"); figF = L[i2:j2]

capR = (B + "caption{Share of attacks that moved money in each evaluation, with no defence, with a spending limit (where "
        "measured) and with the gate. Each row is a separate evaluation; the gate's result is zero in all seven. The "
        "AgentDojo row contains only attacks that had already succeeded against the agent, so the undefended rate is 100" + B +
        "% by construction and only the spending limit is shown; 299 of these attacks had also passed an existing defence "
        "(a prompt-injection detector, tool filter, spotlighting or Meta-SecAlign). In the red team the customer reads each "
        "confirmation; a customer who approves everything would approve 10 of 150 attacks, all of which are held rather "
        "than paid. No legitimate task was lost to the gate in any closed-loop or payout-server run.}\n")
figR = figR[:figR.index(B + "caption{")] + capR + figR[figR.index(B + "label{fig:results}"):]
capF = (B + "caption{How the gate decides a single payment. The payee is classified by its source, using only records the "
        "bank holds, and later checks can only make the decision stricter. Injected text can therefore push a payee down "
        "to class W but cannot raise it to P, K or R. The gate uses no model and makes no network call (median 74" + B + "," +
        B + "textmu s per decision).}\n")
figF = figF[:figF.index(B + "caption{")] + capF + figF[figF.index(B + "label{fig:flow}"):]

ad1 = between(B + "subsection{External, pre-registered: AgentDojo banking (all six predictions held)}", B + "subsection{Every banking run")
ad2 = between(B + "subsection{Every banking run in AgentDojo, including runs behind existing defences (pre-registered)}", B + "subsection{White-box red team")
rt = between(B + "subsection{White-box red team: agent fully hijacked}", B + "subsection{Tests that can fail}")
rt = rt[rt.index(B + "begin{center}" + B + "small"):]
tests = between(B + "subsection{Tests that can fail}", B + "subsection{Closed loop with real LLMs")
closed = between(B + "subsection{Closed loop with real LLMs (pre-registered)}" + B + "label{sec:closed}", B + "subsection{In front of a real")
real = between(B + "subsection{In front of a real, unmodified Indian payout tool (pre-registered)}" + B + "label{sec:realtool}", B + "subsection{Lineage")
deploy = between(B + "section{How a bank deploys it}", B + "section{Deliverables and declarations}")
inst = between(B + "section{What each institution gets, and the rule it already has that this fits}", B + "textbf{How we keep the evidence ahead.}")
related = between(B + "section{Related work, and what is new}", B + "section{How we evaluated it}")
related = related.replace(B + "subsection*{Concurrent work in October 2026, and where we stand}", B + "paragraph{Concurrent work, October 2026.}")
sources = L[L.index(B + "section*{Sources}"):L.index(B + "end{document}")]

coached = (B + "subsection{Coached customers and timed holds (design results)}\n"
           "Provenance cannot see a customer who really typed the scammer's account. A separate check for human payments uses "
           "signals a banking app already has (a call with an unknown number, screen sharing or remote access, more than half "
           "the balance sent in 24 h, a new payee) and holds such a payment for 24 h with a bank call-back. On 120 synthetic "
           "scenarios we wrote from reported Indian fraud patterns, digital arrest, impersonation calls, remote-access refunds "
           "and balance drains were each held 10/10, and a pasted investment VPA was held 8 times and stepped up twice. " + B +
           "textbf{Open:} a victim coached earlier, with no live signal, paying a small amount under the cap is paid 10/10. "
           "Cost: 50/60 legitimate payments go through at once; the 10 held are a large first payment to a car dealer who is on "
           "the phone, which looks exactly like coaching.\n\n"
           "For agent payments, a confirmed step-up becomes a hold (4 h for a new payee, 1 h otherwise) with a cancel link to "
           "the customer's registered contact. Precedents: UK FCA FG24/6 (delay of up to 4 business days on reasonable "
           "suspicion); DBS's new-payee cooling period (March 2026); Singapore banks' block-or-delay on transfers of more than "
           "half the balance (October 2025). Whether a held victim cancels depends on people and is not measured here.\n\n")

ev = (B + "subsection{AgentDojo banking: four frontier models (pre-registered)}\n" + ad1 +
      B + "subsection{Every AgentDojo banking run, including runs behind existing defences (pre-registered)}\n" + ad2 +
      B + "subsection{Closed loop with three real LLMs (pre-registered)}" + B + "label{sec:closed}\n" + closed +
      B + "subsection{In front of a real, unmodified Indian payout server (pre-registered)}" + B + "label{app:realtool}" + B + "label{sec:realtool}\n" + real +
      B + "subsection{White-box red team: agent fully hijacked (design results)}\n" + rt + coached +
      B + "subsection{Tests that can fail}\n" + tests)
dep = deploy + B + "subsection*{Where it fits existing rules}\n" + inst

out = pre + body.replace("%%FIG_FLOW%%", figF).replace("%%FIG_RESULTS%%", figR).replace("%%EVIDENCE%%", ev) \
    .replace("%%DEPLOY%%", dep).replace("%%RELATED%%", related).replace("%%SOURCES%%", sources)

# plain-language fixes to vetted appendix text
out = sub_once(out, B + "textbf{The server already asks the right question, and lets the agent answer it.}",
               B + "textbf{The server's own provenance labels.}")
out = sub_once(out, "Self-reported provenance is testimony, and the attacker controls the testimony. Our gate ignores the label",
               "Because the agent writes these labels, an attacker who controls the agent's inputs in effect writes them too. "
               "Our gate ignores the label")
out = sub_once(out, B + "textbf{The principle is shared; our contribution is the evidence and the gaps closed.}",
               B + "textbf{How our work differs.}")
out = sub_once(out, "The hackathon is where this starts, not where it ends. Each row below names an instrument that already "
               "exists, so adoption needs no new regulation, only a field, a check or a test.",
               "Each row names an instrument that already exists, so adoption needs a new field, check or test rather than "
               "new regulation.")
assert "%%" not in out.replace(B + "%", "")
open(RD + "report.tex", "w", encoding="utf-8").write(out)
print("ok", len(out))
