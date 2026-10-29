"""Record a silent, captioned end-to-end demo video of the prototype.

Run: python record_demo.py  ->  demo/pramaan-demo.mp4 (1920x1080, no audio)
Regenerates data/ first, so the demo starts clean. Rule files are restored afterwards.
Run bench.py first: the closing card quotes bench/results.json.
"""
import http.cookiejar
import json
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

import checks
import gen_data

BASE = Path(__file__).parent
OUT = BASE / "demo"
PORT = 8010
URL = f"http://127.0.0.1:{PORT}/"
PASSWORD = {u: v[2] for u, v in gen_data.DEMO_USERS.items()}

INIT = r"""
HTMLDialogElement.prototype.showModal = function () { this.show(); };  // keep captions above the evidence viewer
window.addEventListener('DOMContentLoaded', () => {
  const s = document.createElement('style');
  s.textContent = `
    .menubar,main,#login{zoom:1.25}
    dialog[open]{position:fixed;top:46%;left:50%;transform:translate(-50%,-50%);z-index:9000;zoom:1.15;max-height:74vh;overflow:auto;
      box-shadow:0 0 0 4000px rgba(0,0,0,.4)}
    #__cap{position:fixed;left:50%;bottom:30px;transform:translateX(-50%);max-width:1600px;background:rgba(0,0,0,.86);color:#fff;
      font:500 30px/1.35 Inter,Arial,sans-serif;padding:14px 30px;border-radius:14px;z-index:99999;text-align:center;opacity:0;
      transition:opacity .25s;pointer-events:none}
    #__card{position:fixed;inset:0;background:#f5f5f5;color:#000;display:none;flex-direction:column;align-items:center;
      justify-content:center;z-index:100000;text-align:center;font-family:Inter,Arial,sans-serif;padding:0 160px;
      background-image:radial-gradient(rgba(0,0,0,.09) 1px,transparent 1.2px);background-size:34px 34px}
    #__card svg{width:110px;height:110px;margin-bottom:10px}
    #__card h1{font-size:104px;font-weight:500;margin:0;letter-spacing:-4px}
    #__card h1 span{font-family:Hind,sans-serif;color:rgba(0,0,0,.45);font-size:64px;letter-spacing:0}
    #__card h2{font-size:64px;font-weight:600;margin:0 0 10px;letter-spacing:-2px}
    #__card p{font-size:36px;color:rgba(0,0,0,.72);margin:18px 0 0;line-height:1.4}
    #__card .k{display:flex;gap:26px;margin-top:40px}
    #__card .k div{background:#fff;border:1px solid rgba(0,0,0,.2);border-radius:12px;padding:22px 30px;min-width:250px;box-shadow:0 10px 24px rgba(0,0,0,.1)}
    #__card .k b{display:block;font-size:60px;font-weight:600;line-height:1.1}
    #__card .k span{font-size:22px;color:rgba(0,0,0,.55)}
    #__cur{position:fixed;width:22px;height:22px;border:3px solid #fff;background:rgba(10,108,255,.9);border-radius:50%;
      z-index:100001;pointer-events:none;transform:translate(-50%,-50%);box-shadow:0 0 0 1.5px rgba(0,0,0,.5);left:-60px;top:-60px}`;
  document.head.appendChild(s);
  for (const id of ['__cap', '__card', '__cur']) { const d = document.createElement('div'); d.id = id; document.body.appendChild(d); }
  document.addEventListener('mousemove', e => {
    const c = document.getElementById('__cur'); c.style.left = e.clientX + 'px'; c.style.top = e.clientY + 'px';
  }, true);
});
window.__cap = t => { const c = document.getElementById('__cap'); c.textContent = t; c.style.opacity = t ? 1 : 0; };
window.__card = html => { const c = document.getElementById('__card'); c.innerHTML = html;
  c.style.display = html ? 'flex' : 'none'; };
"""
MARK = ('<svg viewBox="0 0 24 24"><circle cx="12" cy="4.3" r="3.1"/><path d="M9.7 7.1h4.6l1.15 5.5H8.55z"/>'
        '<rect x="3.4" y="12.4" width="17.2" height="4.4" rx="1.4"/><path d="M8.1 19.9l2.5 2.3 5.3-4.5" fill="none" '
        'stroke="#000" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>')


def record(bench):
    reason = {"text": ""}
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1920, "height": 1080}, record_video_dir=str(OUT / "raw"),
                                  record_video_size={"width": 1920, "height": 1080}, accept_downloads=True)
        ctx.add_init_script(INIT)
        page = ctx.new_page()
        page.on("dialog", lambda d: d.accept(reason["text"]))
        page.goto(URL)
        page.wait_for_load_state("networkidle")

        def wait(s):
            page.wait_for_timeout(int(s * 1000))

        def cap(text, s=3.5):
            page.evaluate("t => window.__cap(t)", text)
            wait(s)

        def card(html, s=4, keep=False):
            page.evaluate("h => window.__card(h)", html)
            wait(s)
            if not keep:
                page.evaluate("() => window.__card('')")

        def show(loc):
            loc.first.evaluate("e => e.scrollIntoView({behavior: 'smooth', block: 'center'})")
            wait(0.9)

        def move(loc):
            b = loc.bounding_box()
            page.mouse.move(b["x"] + b["width"] / 2, b["y"] + b["height"] / 2, steps=20)
            return b

        def click(loc, pause=0.8):
            loc = loc.first
            show(loc)
            b = move(loc)
            wait(0.25)
            page.mouse.click(b["x"] + b["width"] / 2, b["y"] + b["height"] / 2)
            wait(pause)

        def typ(loc, text, delay=35):
            click(loc, 0.2)
            page.keyboard.type(text, delay=delay)

        def top():
            page.evaluate("() => window.scrollTo({top: 0, behavior: 'smooth'})")
            wait(0.7)

        def sign_in(user):
            if page.locator("body.signed").count():
                click(page.get_by_role("button", name="sign out"), 1)
                page.wait_for_selector("#lu", state="visible")
            click(page.locator(".pill", has_text=user), 0.2)
            page.keyboard.type(PASSWORD[user], delay=18)  # masked on screen; demo passwords live in README only
            click(page.get_by_role("button", name="sign in"), 0.8)
            page.wait_for_selector("body.signed")
            wait(0.4)

        def nav(name):
            top()
            click(page.locator(f"nav button[data-t={name}]"), 0.8)

        def open_app(name):
            top()
            click(page.locator("#list .row.q", has_text=name))
            wait(0.6)

        def run():
            click(page.locator("#runBtn"), 0.3)
            page.wait_for_function("() => document.querySelector('#runBtn') && !document.querySelector('#runBtn').disabled",
                                   timeout=180000)
            wait(0.8)

        def finding(title):
            return page.locator(".row.finding", has_text=title)

        def evidence(title, text, s=4.5):
            click(finding(title).get_by_role("button", name="view"))
            wait(0.6)
            cap(text, s)
            click(page.locator("#ev .linkbtn"), 0.5)

        card(f'{MARK}<h1>pramaan <span>प्रमाण</span></h1><p>proof, not just paperwork, for AICTE approvals<br>SIH 2026 · PS 26261 · Team Lucipher</p>', 3.5)
        card('<h2>This already happens</h2><p><b>353 teachers</b> listed full-time at 2+ colleges, one at 11 (Anna University, 2023-24).<br>'
             '<b>52 of 142</b> fire NOCs forged in one Telangana check (2026).<br>'
             'EoA on Self-Disclosure: <b>no scrutiny, no expert visit</b> before approval (APH Table 2.3).<br><br>'
             'Pramaan shows how much of each approval is <b>proven</b>, catches what no single document can show, '
             'and tells AICTE where to inspect first.</p>', 7.5)

        # 0. sign in
        move(page.locator(".hero"))
        cap("Pramaan means “proof”. Every user signs in; the role comes from the server, never the browser.", 3.5)

        # 1. institution pre-check, fix, submit
        sign_in("1-444444")
        cap("1 · College side: Kaveri College runs a pre-check before it submits.", 2.5)
        open_app("Kaveri")
        run()
        show(page.locator("h4", has_text="Pre-check results"))
        cap("Found before AICTE sees it: an expired fire NOC and missing audited accounts.", 3)
        for doc, name in (("fire_noc.pdf", "fire_noc_renewed.pdf"), ("audited_accounts.pdf", "audited_accounts.pdf")):
            row = page.locator(".row.upload", has_text=doc)
            row.locator("input[type=file]").set_input_files(str(gen_data.DATA / "inbox" / name))
            click(row.get_by_role("button", name="upload"), 0.8)
        top()
        run()
        show(page.locator("#submitBtn"))
        cap("Fixed and re-checked: the submit button unlocks only when nothing is left to fix.", 2.5)
        click(page.locator("#submitBtn"), 0.8)

        # 2. officer: the main case
        sign_in("officer.k")
        cap("2 · Scrutiny officer: every submitted application, highest risk first.", 2.5)
        open_app("Sri Rama")
        run()
        cap("Sri Rama Institute: 10 findings, each in plain words with its APH clause. Inspection recommended.", 3.5)
        evidence("Part of the scan looks edited", "The fire NOC scan says “valid until 2027”, but that line was pasted in. The edited area shows in red.", 4.5)
        show(finding("Issuing office's record disagrees"))
        cap("The fire department's own record confirms it: the NOC expired on 08-10-2026.", 3)
        evidence("Photo reused from another college", "This lab photo was already submitted by another college.", 3)
        show(finding("Faculty also listed at another college"))
        cap("Ghost faculty: 4 teachers are also on another college's list this year, matched by PAN. No single document shows this.", 5)
        show(page.locator("#proofHead"))
        page.mouse.wheel(0, 180)
        cap("A proof level for every claim. Score 39: only 33% of what this college declared is independently confirmed; 4 claims are contradicted.", 5.5)

        # 3. change since the last approval, and an office going offline
        open_app("Nalanda")
        page.wait_for_selector("#changeHead")
        show(page.locator("#changeHead"))
        cap("What changed since the last approval: intake tripled from 60 to 180 seats, same classrooms, same building.", 5)

        # 4. review: reasons are mandatory
        open_app("Sri Rama")
        reason["text"] = "Name variant confirmed on registered trust deed"
        click(finding("College name differs").get_by_role("button", name="dismiss"), 0.8)
        reason["text"] = ""
        page.evaluate("""async () => {
            const r = await (await fetch(`/api/apps/${current}`)).json();
            for (const f of r.run.findings.filter(f => f.status === 'OPEN'))
                await fetch(`/api/apps/${current}/findings/${f.id}/review`, {method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({verdict: 'ACCEPTED', reason: ''})});
            await openApp(current); }""")
        cap("The officer reviews every finding; dismissing one needs a written reason. All logged under their own sign-in.", 3.5)

        # 5. the AI cannot decide
        sign_in("pramaan-ai")
        open_app("Sri Rama")
        show(page.locator("#decisionHead"))
        page.select_option("#dOutcome", "ORDER_INSPECTION")
        click(page.get_by_role("button", name="record decision"), 0.8)
        cap("The AI service tries to order an inspection itself: refused (HTTP 403). AI flags, humans decide.", 4)

        # 6. approver proposes, a second officer must confirm
        sign_in("approver.r")
        open_app("Sri Rama")
        show(page.locator("#decisionHead"))
        page.select_option("#dOutcome", "ORDER_INSPECTION")
        typ(page.locator("#dReason"), "Edited fire NOC, reused photo, ghost faculty", 22)
        typ(page.locator("#dChecker"), "officer.k", 40)
        click(page.get_by_role("button", name="record decision"), 1)
        show(page.locator("#decisionHead"))
        cap("3 · The approver proposes an inspection. It is not final until a second officer confirms it.", 4)

        # 7. approval -> signed record anyone can check
        open_app("Vidya")
        show(page.locator("#decisionHead"))
        page.select_option("#dOutcome", "APPROVE")
        click(page.get_by_role("button", name="record decision"), 1)
        show(page.locator("#record"))
        cap("A clean college is approved. Pramaan issues a record signed with AICTE's key, with a QR code.", 3.5)
        rid = page.locator("#record .t").inner_text().split()[-1]
        original = urllib.request.urlopen(f"{URL}api/public/records/{rid}/pdf").read()
        (gen_data.DATA / "inbox" / f"{rid}.pdf").write_bytes(original)
        (gen_data.DATA / "inbox" / "forged_copy.pdf").write_bytes(gen_data.forge_record(original, "Approved Intake", "300"))
        click(page.locator("#publicLink"), 1.2)
        page.mouse.wheel(0, 330)
        cap("Scanning the QR opens a public page, no sign-in: students and parents see what was verified and what was only declared.", 5)
        top()
        page.locator("#file").set_input_files(str(gen_data.DATA / "inbox" / "forged_copy.pdf"))
        click(page.get_by_role("button", name="check this copy"), 1.5)
        cap("A copy with the intake changed from 180 to 300. It looks perfect to the eye.", 3)
        show(page.locator(".verdict"))
        cap("Caught: edited after AICTE signed it. The register still says 180.", 4)
        top()
        click(page.locator("#deskLink"), 1)

        # 8. rules from a circular
        nav("rules")
        page.locator("#normsFile").set_input_files(str(gen_data.DATA / "inbox" / "norms_circular_2026-27.pdf"))
        click(page.get_by_role("button", name="import from file"), 1)
        cap("4 · Norms are not hard-coded: import AICTE's circular, review the highlighted change, publish.", 4)
        click(page.get_by_role("button", name="publish rules"), 0.8)

        # 8b. where to inspect first
        nav("inspect")
        page.wait_for_selector("#planBody .row")
        cap("5 · AICTE has few inspection teams. Pramaan ranks colleges by how little of their claim is proven, and explains why.", 4.5)
        page.mouse.wheel(0, 200)
        cap("Colleges that share faculty or photos go into the same visit. The plan is advice; officers decide.", 4)

        # 9. the second officer confirms
        sign_in("officer.k")
        nav("alerts")
        cap("The named second officer gets an alert and must confirm in their own sign-in.", 3)
        click(page.locator("#alertsBody .row.q", has_text="awaiting your confirmation"), 1)
        show(page.locator("#confirmRow"))
        click(page.get_by_role("button", name="confirm decision"), 0.5)
        page.wait_for_selector("text=confirmed by officer.k")
        wait(0.5)
        show(page.locator("text=confirmed by officer.k"))
        cap("Confirmed. Inspection ordered by two officers, never by the AI.", 3)
        nav("audit")
        cap("Every sign-in, check, review and decision is in a tamper-evident log. Edit one entry and the chain breaks.", 4)
        page.evaluate("() => window.__cap('')")

        s = bench["summary"]
        card(f'<h2>Measured, not claimed</h2><p>{s["applications"]} randomised synthetic applications '
             f'with planted defects, held-out seed, laptop CPU only</p><div class="k">'
             f'<div><b>{s["recall"]:.0%}</b><span>of planted defects caught</span></div>'
             f'<div><b>{s["precision"]:.0%}</b><span>of flags correct</span></div>'
             f'<div><b>{s["median_seconds_per_app"]:g} s</b><span>median per application</span></div></div>', 5)
        card('<h2>What only Pramaan does</h2><p>A proof level for every claim, not just a checklist.<br>'
             'Checks across colleges and years: ghost faculty, reused photos, unexplained growth.<br>'
             'A signed approval record that any student can verify.</p>', 5.5)
        card(f'{MARK}<h1>pramaan <span>प्रमाण</span></h1><p>From self-disclosure to verified disclosure.<br>AI flags. Officers decide.</p>', 3.5, keep=True)
        video = page.video.path()
        ctx.close()
        browser.close()
    return Path(video)


def warm():
    """Run checks on the submitted applications so the queue is sorted by risk when the officer opens it."""
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    opener.open(urllib.request.Request(f"{URL}api/login", data=json.dumps(
        {"username": "officer.k", "password": PASSWORD["officer.k"]}).encode(), headers={"Content-Type": "application/json"}))
    for a in ("APP-1", "APP-2", "APP-3"):
        opener.open(urllib.request.Request(f"{URL}api/apps/{a}/run", method="POST"), timeout=300)


def main():
    bench = json.loads((BASE / "bench" / "results.json").read_text())
    gen_data.build()
    backups = {f: f.read_text(encoding="utf-8") for f in (checks.RULES_FILE, checks.NORMS_FILE)}
    shutil.rmtree(OUT, ignore_errors=True)
    server = subprocess.Popen([sys.executable, "-m", "uvicorn", "app:app", "--port", str(PORT), "--log-level", "warning"],
                              cwd=BASE)
    try:
        for _ in range(60):
            try:
                urllib.request.urlopen(URL, timeout=1)
                break
            except OSError:
                time.sleep(0.5)
        warm()
        raw = record(bench)
    finally:
        server.terminate()
        for f, text in backups.items():
            f.write_text(text, encoding="utf-8")
    mp4 = OUT / "pramaan-demo.mp4"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(raw), "-vf", "setpts=PTS/1.4", "-an", "-c:v", "libx264",
                    "-crf", "18", "-preset", "medium", "-pix_fmt", "yuv420p", "-r", "30", str(mp4)], check=True)
    shutil.rmtree(OUT / "raw")
    print("Wrote", mp4)


if __name__ == "__main__":
    main()
