"""Draw the README's headline results chart as two SVGs (light and dark), from the numbers in the report.

    python media/make_readme_figures.py      # writes media/results-light.svg and media/results-dark.svg

Every value is the share of attack episodes in which money moved (or would have) with no defence; the gate's value is
0 in every row. Sources: Appendix A of AegisAI_Report.pdf and the pre-registrations named in the README.
"""
import os
from xml.sax.saxutils import escape

HERE = os.path.dirname(os.path.abspath(__file__))

GROUPS = [
    ("Real payment providers' systems (test mode / sandbox)", [
        ("Provider 1 sandbox API: payouts", "gpt-4.1-mini, n=15", 73.3),
        ("Provider 2 payout API: payouts", "gpt-4.1-mini, n=15", 66.7),
        ("Provider 3 UPI sandbox: collect requests", "gpt-4.1-mini, n=15", 100.0),
        ("Provider 3 UPI sandbox: Autopay mandates", "gpt-4.1-mini, n=15", 66.7),
        ("Provider 3 UPI sandbox: swapped QR on bills", "gpt-4.1-mini, n=15", 100.0),
    ]),
    ("Real open-source payout server", [
        ("Payout server, gpt-4.1-mini", "n=15", 66.7),
        ("Payout server, gemma4", "n=15", 93.3),
    ]),
    ("Closed loop, three model families", [
        ("gpt-4.1-mini", "n=45", 44.4),
        ("gpt-oss-120b", "n=44", 31.8),
        ("gemma4", "n=45", 26.7),
    ]),
    ("Red team and benchmark", [
        ("Red team, agent fully hijacked", "n=150", 100.0),
        ("AgentDojo, attacks that succeeded", "n=1,477", 100.0),
    ]),
]

THEMES = {
    "light": dict(bg="#fcfcfb", ink="#1f1f1d", ink2="#5f5e58", grid="#e6e5e0", rail="#d3d2cc",
                  none="#eb6834", gate="#2a78d6"),
    "dark": dict(bg="#1a1a19", ink="#f0efec", ink2="#c3c2b7", grid="#2e2e2c", rail="#4a4a46",
                 none="#d95926", gate="#3987e5"),
}

W, LEFT, RIGHT, TOP, ROW, GAP = 920, 380, 60, 92, 26, 30


def svg(theme):
    c = THEMES[theme]
    rows = sum(len(g[1]) for g in GROUPS)
    h = TOP + rows * ROW + len(GROUPS) * GAP + 56
    x0, x1 = LEFT, W - RIGHT

    def X(v):
        return x0 + (x1 - x0) * v / 100.0

    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{h}" viewBox="0 0 {W} {h}" '
         f'font-family="-apple-system,Segoe UI,Helvetica,Arial,sans-serif" role="img" '
         f'aria-label="Share of attacks that moved money, with no defence and with the provenance gate">',
         f'<rect width="{W}" height="{h}" rx="10" fill="{c["bg"]}"/>',
         f'<text x="24" y="34" font-size="17" font-weight="600" fill="{c["ink"]}">Attacks that moved money: no defence vs the provenance gate</text>',
         f'<text x="24" y="56" font-size="12.5" fill="{c["ink2"]}">Share of attack episodes in which the attacker was paid (or would have been). Gate: 0 in all 12 evaluations.</text>']
    lx = W - RIGHT - 250
    o += [f'<circle cx="{lx}" cy="{76}" r="5.5" fill="{c["none"]}"/>',
          f'<text x="{lx + 12}" y="{80}" font-size="12.5" fill="{c["ink2"]}">no defence</text>',
          f'<path d="M{lx + 110} {70} l6 6 l-6 6 l-6 -6 z" fill="{c["gate"]}"/>',
          f'<text x="{lx + 122}" y="{80}" font-size="12.5" fill="{c["ink2"]}">provenance gate</text>']
    y = TOP
    for gname, items in GROUPS:
        y += GAP
        o.append(f'<text x="24" y="{y - 9}" font-size="12" font-weight="600" fill="{c["ink"]}" '
                 f'letter-spacing="0.2">{escape(gname)}</text>')
        for label, n, v in items:
            cy = y + ROW / 2
            o.append(f'<text x="{x0 - 26}" y="{cy + 4}" font-size="12.5" text-anchor="end" fill="{c["ink"]}">'
                     f'{escape(label)} ({escape(n)})</text>')
            o.append(f'<line x1="{X(0)}" y1="{cy}" x2="{X(v)}" y2="{cy}" stroke="{c["rail"]}" stroke-width="2" '
                     f'stroke-linecap="round"/>')
            o.append(f'<g><title>{escape(label)} ({escape(n)}): {v:g}% with no defence, 0% with the gate</title>'
                     f'<circle cx="{X(v)}" cy="{cy}" r="5.5" fill="{c["none"]}" stroke="{c["bg"]}" stroke-width="2"/>'
                     f'<path d="M{X(0)} {cy - 6.5} l6.5 6.5 l-6.5 6.5 l-6.5 -6.5 z" fill="{c["gate"]}" '
                     f'stroke="{c["bg"]}" stroke-width="2"/></g>')
            o.append(f'<text x="{X(v) + 10}" y="{cy + 4}" font-size="11.5" fill="{c["ink2"]}">{v:g}%</text>')
            o.append(f'<text x="{X(0) - 12}" y="{cy + 4}" font-size="11.5" font-weight="600" text-anchor="end" '
                     f'fill="{c["ink"]}">0</text>')
            y += ROW
    base = y + 8
    for t in (0, 25, 50, 75, 100):
        o.insert(4, f'<line x1="{X(t)}" y1="{TOP + 6}" x2="{X(t)}" y2="{base}" stroke="{c["grid"]}" stroke-width="1"/>')
        o.append(f'<text x="{X(t)}" y="{base + 18}" font-size="11.5" text-anchor="middle" fill="{c["ink2"]}">{t}%</text>')
    o.append(f'<text x="24" y="{h - 12}" font-size="11" fill="{c["ink2"]}">AgentDojo row: only attacks that had already '
             f'succeeded, so 100% by construction. Sources: report Appendix A; pre-registrations in this repository.</text>')
    o.append("</svg>")
    return "\n".join(o)


if __name__ == "__main__":
    for th in THEMES:
        with open(os.path.join(HERE, f"results-{th}.svg"), "w", encoding="utf-8") as f:
            f.write(svg(th))
    print("wrote results-light.svg, results-dark.svg")
