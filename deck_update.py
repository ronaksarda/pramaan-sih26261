"""Update the Canva-exported deck in place: same template, new content on slides 2, 4, 5 and 6.

Run: python deck_update.py  ->  ../SIH-TeamLucipher-v2.pdf (the original PDF is left untouched)
Each changed text area is whited out and repainted as a high-resolution panel in the deck's own fonts
(Arial, Lato, Times), so the rest of every slide stays exactly as designed in Canva.
"""
import json
from pathlib import Path

import pymupdf
from playwright.sync_api import sync_playwright

BASE = Path(__file__).parent
SRC = BASE.parent / "SIH-TeamLucipher.pdf"
OUT = BASE.parent / "SIH-TeamLucipher-v2.pdf"
s = json.loads((BASE / "bench" / "results.json").read_text())["summary"]
BENCH = f"{s['applications']} synthetic apps: {s['recall']:.0%} recall, {s['precision']:.0%} precision, {s['median_seconds_per_app']:g} s each on CPU."

FONTS = '<link href="https://fonts.googleapis.com/css2?family=Lato:wght@400;700;900&family=Black+Ops+One&display=swap" rel="stylesheet">'
BASECSS = "*{margin:0;padding:0;box-sizing:border-box}body{background:#fff;-webkit-font-smoothing:antialiased}"

ARIAL = "font:13.7px/1.5 Arial,sans-serif;color:#000"
BOX = '<div style="{css};padding:{pad}"><b>{title}</b> {text}</div>'
SLIDE2 = [  # the four "Proposed solution" boxes, rewritten around what only Pramaan does
    ((93, 141, 553, 223), "Proof Level for Every Claim:",
     "rates each claim from “declared only” up to “confirmed by the issuing office” and gives one Proof Score, so officers see how much of an application is actually proven."),
    ((122, 241, 590, 327), "Document Integrity & Forensics:",
     "validates digital signatures, catches edits made after signing and pasted-in lines on scans, and verifies documents with issuing offices (fire, DigiLocker, payments)."),
    ((93, 342, 553, 424), "Cross-College & Cross-Year Checks:",
     "finds ghost faculty (same PAN at two colleges), reused photos and intake growth with no new capacity, then plans inspections: least-proven colleges first, linked colleges in one visit."),
    ((122, 446, 590, 530), "Signed Approval Anyone Can Verify:",
     "each approval is signed by AICTE with a QR code; students and parents check any copy on a public page. AI only flags, officers decide (maker-checker)."),
]

LATO = "font:14px/1.42 Lato,sans-serif;color:#3f465c"
SLIDE4 = f"""<div style="{LATO};padding:6px 4px 0 4px">
  <p><b style="color:#000">Measured Benchmark:</b> {BENCH}</p>
  <p style="margin-top:10px"><b style="color:#000">Live Demo, Real Crypto:</b> real sign-in; QR-signed approvals; forged copies caught.</p>
  <p style="margin-top:10px"><b style="color:#000">Cross-College Checks:</b> ghost faculty, reused photos, intake jumps.</p></div>"""

CHALLENGES = [("Degraded, skewed document scans", "Contrast normalization & auto-deskewing"),
              ("Font splicing & stamp tampering", "Edit-signal heatmap & signature checks"),
              ("Issuing office offline", "3 retries, then manual review (no silent pass)"),
              ("Forged approval letters", "AICTE-signed record + public QR check"),
              ("Air-gapped MeghRaj compliance", "Fully offline, containerized images"),
              ("Borderline verification edge-cases", "Human-in-the-loop review (no blind reject)")]
CELL = "font:700 14px Lato;display:flex;align-items:center;height:58px;padding:0 18px;margin-top:9px;border:1px solid transparent"
SLIDE4_TABLE = f"""<div style="padding:12px 4px 0">
  <h2 style="font:900 25.6px Lato;text-align:center;letter-spacing:.2px">CHALLENGES AND SOLUTIONS</h2>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:20px">
    <div style="border:1.2px solid #000;border-radius:2px;height:34px;display:flex;align-items:center;justify-content:center;font:900 14px Lato">CHALLENGE / DEFECT</div>
    <div style="border:1.2px solid #000;border-radius:2px;height:34px;display:flex;align-items:center;justify-content:center;font:900 14px Lato">ENGINEERED STRATEGY</div></div>
  {''.join(f'''<div style="{CELL};{'border-color:#e3e3e3;box-shadow:0 8px 14px -6px rgba(0,0,0,.18)' if i % 2 else ''}">
    <span style="width:50%">{c}</span><span>&rarr;&nbsp; {fix}</span></div>''' for i, (c, fix) in enumerate(CHALLENGES))}
</div>"""

SLIDE5 = """<ul style="font:14.1px/1.25 Arial,sans-serif;color:#000;padding:4px 0 0 18px">
  <li><b>Public Approval Check:</b> scan the QR on any approval; edited copies are caught.</li>
  <li style="margin-top:7px"><b>Proven vs Declared:</b> see what was verified and what was only claimed, before paying fees.</li>
  <li style="margin-top:7px"><b>Fewer “Ghost” Colleges:</b> ghost faculty, reused photos and off-campus GPS flagged.</li></ul>"""

X = '<span style="color:#9a9a9a;font:300 30px Arial">✗</span>'
OK = '<span style="font:700 26px Arial">✓</span>'
P = lambda t: f'<span style="font:700 11px Arial;letter-spacing:1.4px;color:#555">{t}</span>'
COLS = ["Verifies with issuer", "Edit after DSC signing", "Reused photos", "Ghost faculty across colleges",
        "Change since last approval", "Proof level per claim", "Signed approval anyone can verify"]
ROWS = [("Manual scrutiny", [X, X, X, X, P("PARTIAL"), X, X]),
        ("Typical PS 26261 entry*", [P("57%"), P("28%"), P("26%"), P("~10%"), P("RARE"), P("RARE"), P("RARE")]),
        ("Pramaan (ours)", [OK] * 7)]
SLIDE6_TABLE = f"""<table style="border-collapse:collapse;width:100%;font-family:Arial">
  <tr style="height:58px"><th style="border:1px solid #000;text-align:left;padding:0 12px;font:700 15px 'Times New Roman';letter-spacing:.6px;width:150px">COMPARISON</th>
  {''.join(f'<th style="background:#111;color:#fff;border:1px solid #000;font:700 11.5px/1.25 Arial;padding:0 5px">{c}</th>' for c in COLS)}</tr>
  {''.join(f'''<tr style="height:62px;{'background:#e6e6e6' if i == 2 else ''}"><td style="border:1px solid #000;padding:0 12px;font:700 13px Arial">{name}</td>
    {''.join(f'<td style="border:1px solid #000;text-align:center">{v}</td>' for v in vals)}</tr>''' for i, (name, vals) in enumerate(ROWS))}
</table>
<p style="font:10px/1.35 Arial;color:#333;margin-top:6px">✓ supported · ✗ not supported · PARTIAL limited / manual ·
 *share of 57 public GitHub repos for PS 26261 whose README mentions the feature (keyword match, Oct 2026)</p>"""

INSIGHTS = [("0", "scrutiny steps for EoA on Self-Disclosure", "APH Table 2.3"),
            ("9,060", "duplicate faculty entries in AICTE-approved institutes", "Lok Sabha reply"),
            ("353", "teachers listed full-time at 2+ colleges, one at 11", "Anna Univ. 2023-24, The News Minute"),
            ("52/142", "fire NOCs found forged in one Telangana check", "Aug 2026, Careers360 / Telangana Today")]
SLIDE6_INSIGHTS = f"""<div style="border:1.3px solid #000;border-radius:4px;height:100%;padding:8px 16px">
  <h3 style="font:700 19px 'Times New Roman';letter-spacing:.4px;padding-bottom:6px;border-bottom:1px solid #bbb">KEY RESEARCH INSIGHTS</h3>
  {''.join(f'''<div style="display:flex;align-items:center;gap:10px;height:54px;border-bottom:1px solid #ddd">
    <b style="font:400 25px 'Black Ops One';min-width:112px">{n}</b>
    <span style="font:12.5px/1.25 Arial">{t} <span style="color:#777;font-size:10.5px">({src})</span></span></div>''' for n, t, src in INSIGHTS)}
</div>"""


def panels(specs):
    """Render each HTML panel at 4x so it stays sharp in the PDF."""
    out = []
    with sync_playwright() as p:
        b = p.chromium.launch()
        for (x0, y0, x1, y1), html in specs:
            pg = b.new_page(viewport={"width": int(x1 - x0), "height": int(y1 - y0)}, device_scale_factor=4)
            pg.set_content(f"<html><head>{FONTS}<style>{BASECSS}</style></head><body>{html}</body></html>")
            pg.wait_for_load_state("networkidle")
            pg.evaluate("document.fonts.ready")
            out.append(pg.screenshot())
            pg.close()
        b.close()
    return out


def main():
    doc = pymupdf.open(SRC)
    edits = {1: [(r, BOX.format(css=ARIAL, pad="2px 6px", title=t, text=x)) for r, t, x in SLIDE2],
             3: [((40, 466, 374, 630), SLIDE4), ((397, 150, 1034, 648), SLIDE4_TABLE)],
             4: [((1030, 360, 1345, 486), SLIDE5)],
             5: [((34, 456, 858, 732), SLIDE6_TABLE), ((874, 456, 1386, 732), SLIDE6_INSIGHTS)]}
    for pn, items in edits.items():
        page = doc[pn]
        for (rect, _), png in zip(items, panels(items)):
            r = pymupdf.Rect(rect)
            page.add_redact_annot(r, fill=(1, 1, 1))
            page.apply_redactions(images=pymupdf.PDF_REDACT_IMAGE_NONE, graphics=pymupdf.PDF_REDACT_LINE_ART_NONE)
            page.draw_rect(r, color=None, fill=(1, 1, 1))  # cover image pixels under the panel too
            page.insert_image(r, stream=png)
    doc.save(OUT, garbage=3, deflate=True)
    print("Wrote", OUT, f"{OUT.stat().st_size / 1e6:.1f} MB")


if __name__ == "__main__":
    main()
