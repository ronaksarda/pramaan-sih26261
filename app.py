"""Pramaan prototype API + dashboard.

Run:  python gen_data.py   then   python -m uvicorn app:app --port 8000   and open http://localhost:8000
"""
import base64
import hashlib
import io
import json
import os
import secrets
import zipfile
from datetime import date, datetime, timedelta

import numpy as np
import pymupdf
from fastapi import FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from PIL import Image, ImageDraw
from pydantic import BaseModel

import auth
import anthropic

import assistant
import checks
import records
import storage

DATA = checks.DATA
STATE = DATA / "state.json"
AUDIT = DATA / "audit.jsonl"
OFFICERS = {"scrutiny_officer", "approver"}
MAX_UPLOAD = 20 * 1024 * 1024
OPEN_PATHS = ("/api/login", "/api/me", "/api/public/", "/api/webhook/")  # the webhook has its own portal token

app = FastAPI(title="Pramaan")


@app.middleware("http")
async def session(request: Request, call_next):
    """Role and user come only from a verified session cookie; any X-Role/X-User a client sends is dropped.
    An institution's username is its AICTE ID."""
    user = auth.read(request.cookies.get(auth.COOKIE))
    headers = [(k, v) for k, v in request.scope["headers"] if k not in (b"x-role", b"x-user")]
    if user:
        headers += [(b"x-role", user["role"].encode()), (b"x-user", user["username"].encode())]
    request.scope["headers"] = headers
    if request.url.path.startswith("/api/") and not user and not request.url.path.startswith(OPEN_PATHS):
        return JSONResponse({"detail": "Sign in first"}, 401)
    return await call_next(request)


class Login(BaseModel):
    username: str
    password: str


@app.post("/api/login")
def login(body: Login):
    user = auth.check(body.username.strip(), body.password)
    if not user:
        audit("anonymous", "LOGIN_FAILED", {})
        raise HTTPException(401, "Wrong username or password")
    audit(f"{user['role']}:{user['username']}", "LOGIN", {})
    r = JSONResponse(user)
    r.set_cookie(auth.COOKIE, auth.issue(user), max_age=auth.TTL, httponly=True, samesite="strict")
    return r


@app.post("/api/logout")
def logout():
    r = JSONResponse({"ok": True})
    r.delete_cookie(auth.COOKIE)
    return r


@app.get("/api/me")
def me(request: Request):
    return auth.read(request.cookies.get(auth.COOKIE))


def load():
    s = json.loads(STATE.read_text()) if STATE.exists() else {}
    return {"runs": {}, "decisions": {}, "records": {}, **s}


def save(s):
    STATE.write_text(json.dumps(s, indent=1))


def audit(actor, action, payload):
    lines = AUDIT.read_text().splitlines() if AUDIT.exists() else []
    e = {"ts": datetime.now().isoformat(timespec="seconds"), "actor": actor, "action": action, "payload": payload,
         "prev_hash": json.loads(lines[-1])["hash"] if lines else "GENESIS"}
    e["hash"] = hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest()
    with AUDIT.open("a") as f:
        f.write(json.dumps(e) + "\n")


def verify_chain():
    lines = AUDIT.read_text().splitlines() if AUDIT.exists() else []
    prev = "GENESIS"
    for i, line in enumerate(lines):
        e = json.loads(line)
        h = e.pop("hash")
        if e["prev_hash"] != prev or hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest() != h:
            return {"ok": False, "entries": len(lines), "broken_at": i}
        prev = h
    return {"ok": True, "entries": len(lines)}


def application(app_id):
    p = DATA / "apps" / app_id / "application.json"
    if not app_id.replace("-", "").isalnum() or not p.exists():
        raise HTTPException(404, "unknown application")
    return json.loads(p.read_text())


def visible(a, role, user):
    if role == "institution":
        return a["aicte_id"] == user
    return a["status"] in ("SUBMITTED", "RECTIFICATION")


def safe_path(app_id, doc):
    """Trust boundary: only files inside one application's folder can be served."""
    application(app_id)
    root = (DATA / "apps" / app_id).resolve()
    p = (root / doc).resolve()
    if root not in p.parents or not p.is_file() or p.name == "application.json":
        raise HTTPException(404, "unknown document")
    return p


@app.get("/api/apps")
def list_apps(x_role: str = Header(""), x_user: str = Header("")):
    s = load()
    out = []
    for p in sorted((DATA / "apps").glob("*/application.json")):
        a = json.loads(p.read_text())
        if not visible(a, x_role, x_user):
            continue
        r = s["runs"].get(a["id"])
        out.append({**a, "outcome": r and r["outcome"], "risk_score": r and r["risk_score"],
                    "open_findings": r and sum(f["status"] == "OPEN" for f in r["findings"]),
                    "decision": s["decisions"].get(a["id"])})
    return sorted(out, key=lambda a: -(a["risk_score"] or 0))


@app.get("/api/apps/{app_id}")
def get_app(app_id: str, x_role: str = Header(""), x_user: str = Header("")):
    a = application(app_id)
    if not visible(a, x_role, x_user):
        raise HTTPException(403, "Not visible to this role")
    s = load()
    docs = sorted(p.name for p in (DATA / "apps" / app_id).glob("*.pdf"))
    return {"application": a, "documents": docs, "run": s["runs"].get(app_id), "decision": s["decisions"].get(app_id),
            "record": next((r for r in s["records"].values() if r["app"] == app_id), None)}


@app.post("/api/apps/{app_id}/run")
def run_checks(app_id: str, x_role: str = Header(""), x_user: str = Header("")):
    a = application(app_id)
    if not visible(a, x_role, x_user):
        raise HTTPException(403, "Not visible to this role")
    r = checks.run(app_id)
    s = load()
    s["runs"][app_id] = r
    s["decisions"].pop(app_id, None)
    save(s)
    audit("ai-service", "RUN_CHECKS", {"app": app_id, "requested_by": f"{x_role}:{x_user}", "rules_version": r["rules_version"],
                                       "outcome": r["outcome"], "findings": [f["check"] for f in r["findings"]],
                                       "sources": {v["doc"]: v["status"] for v in r["verifications"]},
                                       "doc_hashes": r["doc_hashes"], "seconds": r["seconds"]})
    return r


@app.post("/api/apps/{app_id}/documents")
async def upload(app_id: str, doc_type: str = Form(...), file: UploadFile = File(...),
                 x_role: str = Header(""), x_user: str = Header("")):
    a = application(app_id)
    if x_role != "institution" or a["aicte_id"] != x_user:
        raise HTTPException(403, "Only the applying institution can upload")
    if a["status"] not in ("DRAFT", "RECTIFICATION"):
        raise HTTPException(409, "Application already submitted")
    rules = json.loads(checks.RULES_FILE.read_text(encoding="utf-8"))
    if doc_type not in rules["categories"][a["category"]]["required"]:
        raise HTTPException(422, f"{doc_type} is not on the checklist for this category")
    data = await file.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD or not data.startswith(b"%PDF"):
        raise HTTPException(422, "Upload a PDF of at most 20 MB")
    storage.write(DATA / "apps" / app_id / doc_type, data)
    audit(f"institution:{x_user}", "DOCUMENT_UPLOADED", {"app": app_id, "doc": doc_type, "sha256": hashlib.sha256(data).hexdigest()})
    return {"ok": True, "doc": doc_type, "bytes": len(data)}


@app.post("/api/apps/{app_id}/submit")
def submit(app_id: str, x_role: str = Header(""), x_user: str = Header("")):
    a = application(app_id)
    if x_role != "institution" or a["aicte_id"] != x_user:
        raise HTTPException(403, "Only the applying institution can submit")
    run = load()["runs"].get(app_id)
    if not run:
        raise HTTPException(409, "Run the pre-check first")
    if a["status"] == "RECTIFICATION":  # a correction round goes back to the officer even if items remain open
        a.update(status="SUBMITTED", resubmitted_at=datetime.now().isoformat(timespec="seconds"))
    else:
        blocking = [f["check"] for f in run["findings"] if f["action"] == "RECTIFY"]
        if blocking:
            raise HTTPException(409, f"Fix these before submitting: {', '.join(blocking)}")
        a.update(status="SUBMITTED", submitted_at=datetime.now().isoformat(timespec="seconds"))
    (DATA / "apps" / app_id / "application.json").write_text(json.dumps(a, indent=2))
    audit(f"institution:{x_user}", "SUBMITTED", {"app": app_id})
    return a


class Webhook(BaseModel):
    aicte_id: str
    category: str
    proposed_intake: int
    faculty_count: int
    classroom_areas_sqm: list[int]
    building_age_years: int


@app.post("/api/webhook/application")
def webhook(body: Webhook, x_portal_token: str = Header("")):
    """Intake from the AICTE portal: creates a draft the institution then completes."""
    token = os.environ.get("PRAMAAN_PORTAL_TOKEN", "demo-portal-token")
    if not secrets.compare_digest(x_portal_token, token):
        raise HTTPException(401, "bad portal token")
    master = json.loads((DATA / "master.json").read_text())
    rules = json.loads(checks.RULES_FILE.read_text(encoding="utf-8"))
    if body.aicte_id not in master or body.category not in rules["categories"]:
        raise HTTPException(422, "unknown institution or category")
    app_id = f"APP-{len(list((DATA / 'apps').iterdir())) + 1}"
    a = {"id": app_id, "aicte_id": body.aicte_id, "institution": master[body.aicte_id]["name"], "category": body.category,
         "status": "DRAFT", "programme_level": "UG Engineering", "application_date": date.today().isoformat(),
         "submitted_at": datetime.now().isoformat(timespec="seconds"), "photos": [], **body.model_dump(exclude={"aicte_id", "category"})}
    (DATA / "apps" / app_id / "photos").mkdir(parents=True)
    (DATA / "apps" / app_id / "application.json").write_text(json.dumps(a, indent=2))
    audit("aicte-portal", "WEBHOOK_INTAKE", {"app": app_id, "aicte_id": body.aicte_id})
    return {"id": app_id, "status": "DRAFT"}


class Review(BaseModel):
    verdict: str  # ACCEPTED or DISMISSED
    reason: str = ""


@app.post("/api/apps/{app_id}/findings/{fid}/review")
def review(app_id: str, fid: int, body: Review, x_role: str = Header(""), x_user: str = Header("")):
    if x_role not in OFFICERS:
        raise HTTPException(403, "Only a human officer can review findings")
    if body.verdict not in ("ACCEPTED", "DISMISSED"):
        raise HTTPException(422, "verdict must be ACCEPTED or DISMISSED")
    if body.verdict == "DISMISSED" and not body.reason.strip():
        raise HTTPException(422, "A reason is required to dismiss a finding")
    s = load()
    run = s["runs"].get(app_id)
    if not run or not 0 <= fid < len(run["findings"]):
        raise HTTPException(404, "unknown finding")
    f = run["findings"][fid]
    f.update(status=body.verdict, reviewed_by=x_user, review_reason=body.reason)
    save(s)
    audit(f"{x_role}:{x_user}", f"FINDING_{body.verdict}", {"app": app_id, "finding": fid, "check": f["check"],
                                                               "reason": body.reason})
    return f


class Decision(BaseModel):
    outcome: str  # APPROVE, ISSUE_DEFICIENCY, ORDER_INSPECTION
    reason: str = ""
    checker: str = ""


@app.post("/api/apps/{app_id}/decision")
def decide(app_id: str, body: Decision, request: Request, x_role: str = Header(""), x_user: str = Header("")):
    # The AI service and every non-approver role are refused here: decisions are human-only.
    if x_role != "approver":
        raise HTTPException(403, f"Role '{x_role or 'none'}' cannot record a regulatory decision")
    if body.outcome not in ("APPROVE", "ISSUE_DEFICIENCY", "ORDER_INSPECTION"):
        raise HTTPException(422, "unknown outcome")
    s = load()
    run = s["runs"].get(app_id)
    if not run:
        raise HTTPException(409, "Run checks first")
    open_high = [f["check"] for f in run["findings"] if f["severity"] == "HIGH" and f["status"] == "OPEN"]
    if open_high:
        raise HTTPException(409, f"Review every HIGH finding first: {', '.join(open_high)}")
    if body.outcome != "APPROVE":
        if not body.reason.strip():
            raise HTTPException(422, "An adverse decision needs a written reason")
        checker = auth.users().get(body.checker.strip())
        if not checker or checker["role"] not in OFFICERS or body.checker.strip() == x_user:
            raise HTTPException(422, "An adverse decision needs a second officer (checker): another officer's user ID")
    d = {**body.model_dump(), "maker": x_user, "at": datetime.now().isoformat(timespec="seconds"),
         "status": "FINAL" if body.outcome == "APPROVE" else "AWAITING_CHECKER"}
    s["decisions"][app_id] = d
    audit(f"approver:{x_user}", "DECISION" if d["status"] == "FINAL" else "DECISION_PROPOSED", {"app": app_id, **d})
    if body.outcome == "APPROVE":
        rec = {**records.issue(application(app_id), run, d, str(request.base_url)), "watch": []}
        s["records"][rec["id"]] = rec
        d["record"] = rec["id"]
        audit("pramaan-records", "RECORD_ISSUED", {"app": app_id, "record": rec["id"], "sha256": rec["sha256"]})
    save(s)
    return d


class Confirm(BaseModel):
    agree: bool
    note: str = ""


@app.post("/api/apps/{app_id}/decision/confirm")
def confirm(app_id: str, body: Confirm, x_role: str = Header(""), x_user: str = Header("")):
    """Maker-checker: only the officer named as checker, signed in as themself, can confirm or send back."""
    s = load()
    d = s["decisions"].get(app_id)
    if not d or d.get("status") != "AWAITING_CHECKER":
        raise HTTPException(409, "No decision is waiting for confirmation")
    if x_role not in OFFICERS or x_user != d["checker"]:
        raise HTTPException(403, f"Only {d['checker']}, the named checker, can confirm this decision")
    if body.agree:
        d.update(status="FINAL", confirmed_at=datetime.now().isoformat(timespec="seconds"), checker_note=body.note)
        audit(f"{x_role}:{x_user}", "DECISION_CONFIRMED", {"app": app_id, "outcome": d["outcome"], "note": body.note})
        if d["outcome"] == "ISSUE_DEFICIENCY":
            open_rectification(app_id, s["runs"][app_id], d)
    else:
        if not body.note.strip():
            raise HTTPException(422, "Say why you are sending the decision back")
        s["decisions"].pop(app_id)
        audit(f"{x_role}:{x_user}", "DECISION_SENT_BACK", {"app": app_id, "outcome": d["outcome"], "note": body.note})
        d = {**d, "status": "SENT_BACK", "checker_note": body.note}
    save(s)
    return d


def open_rectification(app_id, run, d):
    """A confirmed deficiency letter reopens the application for exactly the accepted findings that need a fix."""
    a = application(app_id)
    rnd = a.get("rectification", {}).get("round", 0) + 1
    items = [{"finding": f["id"], "check": f["check"], "title": f["title"], "message": f["message"],
              "doc": f.get("doc") or next((e["doc"] for e in f["evidence"] if e["app"] == app_id and not e["doc"].startswith("photos/")), "")}
             for f in run["findings"] if f["status"] == "ACCEPTED" and f["action"] in ("RECTIFY", "ADDITIONAL_EVIDENCE")]
    days = json.loads(checks.RULES_FILE.read_text(encoding="utf-8"))["norms"]["rectification_days"]
    rect = {"round": rnd, "items": items, "requested_at": datetime.now().isoformat(timespec="seconds"),
            "due": (date.today() + timedelta(days=days)).isoformat(), "maker": d["maker"], "checker": d["checker"],
            "snapshot": {"doc_hashes": run["doc_hashes"], "fields": {k: v["fields"] for k, v in run["extraction"].items()}}}
    storage.write(DATA / "apps" / app_id / "letters" / f"deficiency-round-{rnd}.pdf", records.deficiency_letter(a, rect))
    a.update(status="RECTIFICATION", rectification=rect)
    (DATA / "apps" / app_id / "application.json").write_text(json.dumps(a, indent=2))
    audit("pramaan-records", "DEFICIENCY_LETTER_ISSUED", {"app": app_id, "round": rnd, "items": [i["title"] for i in items]})


@app.get("/api/apps/{app_id}/letter")
def letter(app_id: str, x_role: str = Header(""), x_user: str = Header("")):
    a = application(app_id)
    if not visible(a, x_role, x_user) or "rectification" not in a:
        raise HTTPException(404, "No deficiency letter for this application")
    rnd = a["rectification"]["round"]
    return Response(storage.read(DATA / "apps" / app_id / "letters" / f"deficiency-round-{rnd}.pdf"), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{app_id}-deficiency-round-{rnd}.pdf"'})


@app.get("/api/apps/{app_id}/revisions")
def doc_revisions(app_id: str, doc: str, x_role: str = Header(""), x_user: str = Header("")):
    """Every saved version inside a PDF, what each one added or removed, and which one the signature covers."""
    if not visible(application(app_id), x_role, x_user):
        raise HTTPException(403, "Not visible to this role")
    data = storage.read(safe_path(app_id, doc))
    ends = checks.revisions(data)
    sig = checks.validate_dsc(data) if doc == "affidavit.pdf" else None
    signed_end = None
    if sig:  # the signature's byte range ends inside the revision it signed
        from pyhanko.pdf_utils.reader import PdfFileReader
        br = PdfFileReader(io.BytesIO(data)).embedded_signatures[0].byte_range
        signed_end = br[2] + br[3]
    out, prev = [], []
    for i, end in enumerate(ends, 1):
        lines = checks.revision_lines(data, end)
        out.append({"rev": i, "bytes": end, "signed": signed_end is not None and abs(end - signed_end) < 64,
                    "after_signing": signed_end is not None and end > signed_end + 64,
                    "added": [ln for ln in lines if ln not in prev], "removed": [ln for ln in prev if ln not in lines]})
        prev = lines
    return {"doc": doc, "revisions": out}


@app.get("/api/apps/{app_id}/revision.png")
def revision_png(app_id: str, doc: str, rev: int, x_role: str = Header(""), x_user: str = Header("")):
    if not visible(application(app_id), x_role, x_user):
        raise HTTPException(403, "Not visible to this role")
    data = storage.read(safe_path(app_id, doc))
    ends = checks.revisions(data)
    if not 1 <= rev <= len(ends):
        raise HTTPException(404, "No such revision")
    return Response(pymupdf.open(stream=data[:ends[rev - 1]])[0].get_pixmap(dpi=80).tobytes("png"), media_type="image/png")


def render_evidence(app, doc, kind, bbox=None, boxes=None):
    data = storage.read(safe_path(app, doc))
    if kind == "img":
        return data
    if kind == "boxes":
        img = Image.open(io.BytesIO(data)).convert("RGB")
        d = ImageDraw.Draw(img)
        for b in boxes or []:
            d.rectangle(b, outline=(255, 59, 48), width=3)
    else:
        page = pymupdf.open(stream=data)[0]
        zoom = 110 / 72
        img = Image.open(io.BytesIO(page.get_pixmap(dpi=110).tobytes("png"))).convert("RGB")
        if kind == "ela":
            jpeg = pymupdf.open(stream=data).extract_image(page.get_images()[0][0])["image"]
            heat, _ = checks.ela_map(jpeg)
            heat = Image.fromarray(np.clip(heat * 10, 0, 255).astype(np.uint8)).resize(img.size)
            red = Image.new("RGB", img.size, (255, 59, 48))
            img = Image.composite(red, img, heat.point(lambda v: min(200, v)))
        if bbox:
            ImageDraw.Draw(img).rectangle([v * zoom for v in bbox], outline=(255, 59, 48), width=3)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


@app.get("/api/evidence")
def evidence(app: str, doc: str, kind: str = "pdf", finding: int = -1, x_role: str = Header(""), x_user: str = Header("")):
    if x_role not in OFFICERS | {"auditor"} and not visible(application(app), x_role, x_user):
        raise HTTPException(403, "Not visible to this role")
    run = load()["runs"].get(app)
    ev = {}
    if run and 0 <= finding < len(run["findings"]):
        ev = next((e for e in run["findings"][finding]["evidence"] if e["doc"] == doc and e["app"] == app), {})
    data = render_evidence(app, doc, kind, ev.get("bbox"), ev.get("boxes"))
    return Response(data, media_type="image/jpeg" if kind == "img" else "image/png")


@app.get("/api/apps/{app_id}/evidence-pack")
def evidence_pack(app_id: str, x_role: str = Header("")):
    if x_role not in OFFICERS | {"auditor"}:
        raise HTTPException(403, "Officers and auditors only")
    s = load()
    run = s["runs"].get(app_id)
    if not run:
        raise HTTPException(409, "Run checks first")
    entries = [json.loads(x) for x in AUDIT.read_text().splitlines() if f'"app": "{app_id}"' in x]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("report.json", json.dumps({"application": application(app_id), "run": run,
                                              "decision": s["decisions"].get(app_id), "audit_chain": verify_chain()}, indent=2))
        z.writestr("audit_entries.jsonl", "\n".join(json.dumps(e) for e in entries))
        for f in run["findings"]:
            for i, e in enumerate(f["evidence"]):
                kind = e["kind"]
                z.writestr(f"evidence/{f['id']:02d}_{f['check']}_{i}.{'jpg' if kind == 'img' else 'png'}",
                           render_evidence(e["app"], e["doc"], kind, e.get("bbox"), e.get("boxes")))
    audit(x_role, "EVIDENCE_PACK_EXPORTED", {"app": app_id})
    return Response(buf.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{app_id}-evidence-pack.zip"'})


class Ask(BaseModel):
    question: str
    app_id: str = ""
    history: list[dict] = []


@app.post("/api/assist")
def assist(body: Ask, x_role: str = Header(""), x_user: str = Header("")):
    """Ask Pramaan. The assistant sees only what this role may see, and never decides."""
    if not body.question.strip() or len(body.question) > 2000:
        raise HTTPException(422, "Ask a question of at most 2000 characters")
    history = [{"role": m["role"], "content": str(m["content"])[:4000]} for m in body.history
               if m.get("role") in ("user", "assistant")]  # trust boundary: only plain user/assistant turns
    if body.app_id:
        a = application(body.app_id)
        if not visible(a, x_role, x_user):
            raise HTTPException(403, "Not visible to this role")
        s = load()
        context = assistant.case_context(a, s["runs"].get(a["id"]), s["decisions"].get(a["id"]),
                                         next((r for r in s["records"].values() if r["app"] == a["id"]), None))
    else:
        context = assistant.queue_context(list_apps(x_role, x_user))
    try:
        answer = assistant.ask(body.question.strip(), history, context, x_role)
    except anthropic.AuthenticationError:
        raise HTTPException(503, "Ask Pramaan needs an Anthropic API key on the server (ANTHROPIC_API_KEY)")
    except anthropic.RateLimitError:
        raise HTTPException(429, "Ask Pramaan is busy. Try again in a minute.")
    except anthropic.APIStatusError as e:
        raise HTTPException(502, f"Ask Pramaan could not answer (model service error {e.status_code})")
    except anthropic.APIConnectionError:
        raise HTTPException(503, "Ask Pramaan cannot reach the model service. Check the server's internet connection.")
    except TypeError as e:  # the SDK raises this when no credential is configured at all
        if "api_key" not in str(e) and "auth" not in str(e).lower():
            raise
        raise HTTPException(503, "Ask Pramaan needs an Anthropic API key on the server (ANTHROPIC_API_KEY)")
    audit(f"{x_role}:{x_user}", "ASSISTANT_QUESTION", {"app": body.app_id or None, "question": body.question.strip()[:300]})
    return {"answer": answer}


@app.post("/api/run-all")
def run_all(x_role: str = Header(""), x_user: str = Header("")):
    """Check every submitted application, as a regional office would at the start of a cycle."""
    if x_role not in OFFICERS:
        raise HTTPException(403, "Officers only")
    t0 = datetime.now()
    s = load()
    ids = [p.parent.name for p in sorted((DATA / "apps").glob("*/application.json"))
           if json.loads(p.read_text())["status"] == "SUBMITTED"]
    for app_id in ids:
        s["runs"][app_id] = checks.run(app_id)
        s["decisions"].pop(app_id, None)
    save(s)
    audit(f"{x_role}:{x_user}", "RUN_ALL", {"applications": len(ids)})
    return {"checked": len(ids), "seconds": round((datetime.now() - t0).total_seconds(), 1)}


@app.get("/api/network")
def network(x_role: str = Header("")):
    """Colleges joined by shared faculty, photos, files or land: patterns no single application shows."""
    if x_role not in OFFICERS | {"auditor"}:
        raise HTTPException(403, "Officers and auditors only")
    s = load()
    nodes, edges = {}, {}
    in_queue = {application(i)["institution"]: i for i in s["runs"]}
    for app_id, run in s["runs"].items():
        a = application(app_id)
        for f in run["findings"]:
            for lk in f.get("links", []):
                other = lk.get("institution") or application(lk["app"])["institution"]
                for name in (a["institution"], other):
                    nodes[name] = {"name": name, "app": in_queue.get(name), "risk": None}
                key = (*sorted((a["institution"], other)), lk["kind"])
                edges[key] = max(edges.get(key, 0), lk.get("count", 1))
    for n in nodes.values():
        if n["app"]:
            n["risk"] = s["runs"][n["app"]]["risk_score"]
    return {"nodes": list(nodes.values()), "edges": [{"a": a, "b": b, "kind": k, "count": c} for (a, b, k), c in edges.items()]}


@app.get("/api/inspection-brief")
def inspection_brief(app: str, x_role: str = Header("")):
    if x_role not in OFFICERS | {"auditor"}:
        raise HTTPException(403, "Officers and auditors only")
    a, run = application(app), load()["runs"].get(app)
    if not run:
        raise HTTPException(409, "Run checks first")
    with_ = sorted({lk.get("institution") or application(lk["app"])["institution"] for f in run["findings"] for lk in f.get("links", [])})
    master = json.loads((DATA / "master.json").read_text())[a["aicte_id"]]
    audit(x_role, "INSPECTION_BRIEF", {"app": app})
    return Response(records.inspection_brief(a, master, run, with_), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{app}-inspection-brief.pdf"'})


@app.get("/api/issuer/fire")
def issuer_fire(x_role: str = Header("")):
    """Issuer simulator: the state fire department's register, as the integration would see it."""
    if x_role not in OFFICERS:
        raise HTTPException(403, "Officers only")
    reg = json.loads((DATA / "registry.json").read_text())["fire"]
    approved = {application(r["app"])["aicte_id"]: r["app"] for r in load()["records"].values()}
    master = json.loads((DATA / "master.json").read_text())
    by_name = {m["name"]: aid for aid, m in master.items()}
    return [{"noc": k, **v, "app": approved.get(by_name.get(v["institution"]))} for k, v in sorted(reg.items())]


class Revoke(BaseModel):
    noc: str


@app.post("/api/issuer/fire/revoke")
def issuer_revoke(body: Revoke, x_role: str = Header(""), x_user: str = Header("")):
    """Simulate the fire department revoking a NOC, then run the post-approval watch."""
    if x_role not in OFFICERS:
        raise HTTPException(403, "Officers only")
    path = DATA / "registry.json"
    reg = json.loads(path.read_text())
    if body.noc not in reg["fire"]:
        raise HTTPException(404, "No such NOC in the fire register")
    reg["fire"][body.noc]["revoked"] = date.today().isoformat()
    path.write_text(json.dumps(reg, indent=2))
    audit(f"{x_role}:{x_user}", "ISSUER_REVOKED", {"source": "fire", "noc": body.noc})
    return {"revoked": body.noc, "watch": watch()}


def watch():
    """Re-verify every approved college with its issuers; record any certificate that is no longer valid."""
    s = load()
    events = []
    for r in s["records"].values():
        before = {v["doc"]: v["status"] for v in s["runs"][r["app"]]["verifications"]}
        run = checks.run(r["app"])
        for v in run["verifications"]:
            if before.get(v["doc"]) == "VERIFIED" and v["status"] != "VERIFIED":
                note = f"{v['doc']}: {v['source']} now reports {v['status'].lower()} (checked {v['checked_at'][:16].replace('T', ' ')})"
                r.setdefault("watch", []).append({"at": v["checked_at"], "doc": v["doc"], "status": v["status"], "note": note})
                events.append({"record": r["id"], "app": r["app"], "note": note})
                audit("pramaan-watch", "CERTIFICATE_CHANGED_AFTER_APPROVAL", {"app": r["app"], "record": r["id"], "note": note})
        s["runs"][r["app"]] = run
    save(s)
    return events


@app.get("/api/inspection-plan")
def inspection_plan(budget: int = 3, x_role: str = Header("")):
    """Self-disclosure approvals are checked only afterwards (APH 2.5(c)) and inspection teams are few.
    Rank colleges by how little of their claim is proven, and keep colleges that share evidence in one visit."""
    if x_role not in OFFICERS | {"auditor"}:
        raise HTTPException(403, "Officers and auditors only")
    s = load()
    master = json.loads((DATA / "master.json").read_text())
    rows = []
    for app_id, run in s["runs"].items():
        a = application(app_id)
        if a["status"] != "SUBMITTED":
            continue
        high = [f for f in run["findings"] if f["severity"] == "HIGH"]
        linked = {lk.get("institution") or application(lk["app"])["institution"] for f in run["findings"] for lk in f.get("links", [])}
        rows.append({"app": app_id, "institution": a["institution"], "state": master[a["aicte_id"]]["state"],
                     "proof": run["proof"]["score"], "contradicted": run["proof"]["counts"]["CONTRADICTED"], "high": len(high),
                     "priority": 10 * run["proof"]["counts"]["CONTRADICTED"] + 5 * len(high) + (100 - run["proof"]["score"]) // 2,
                     "reasons": [f["title"] for f in high][:3], "inspect_with": sorted(linked)})
    rows.sort(key=lambda r: -r["priority"])
    plan, visits = [], 0
    for r in rows:
        cost = 1 + len(r["inspect_with"])  # linked colleges are visited by the same team in the same week
        if visits + cost > max(budget, 1) or r["priority"] == 0:
            continue
        plan.append(r)
        visits += cost
    total_high = sum(r["high"] for r in rows) or 1
    return {"budget": budget, "visits": visits, "plan": plan, "not_planned": [r for r in rows if r not in plan],
            "high_covered_pct": round(100 * sum(r["high"] for r in plan) / total_high)}


@app.get("/api/alerts")
def alerts(x_role: str = Header(""), x_user: str = Header("")):
    """Alerts derived from the latest runs, routed by role."""
    s = load()
    out = []
    route = {"institution": {"DOC_MISSING", "DOC_EXPIRED", "DOC_EXPIRING", "FIELD_MISSING"},
             "scrutiny_officer": {"EDITED_AFTER_SIGNING", "SCAN_TAMPER", "DUPLICATE_PHOTO", "NAME_MISMATCH",
                                  "SIGNATORY_MISMATCH", "SOURCE_MISMATCH", "SCENE_MISMATCH", "GPS_FAR", "FIELD_LOW_CONFIDENCE"},
             "approver": set(), "admin": {"SOURCE_DOWN"}}
    for app_id, run in s["runs"].items():
        a = application(app_id)
        if not visible(a, x_role, x_user) and x_role != "admin":
            continue
        for f in run["findings"]:
            if f["status"] == "OPEN" and f["check"] in route.get(x_role, set()):
                out.append({"app": app_id, "institution": a["institution"], "type": f["check"], "title": f["title"], "severity": f["severity"],
                            "message": f["message"]})
        d = s["decisions"].get(app_id)
        if d and d.get("status") == "AWAITING_CHECKER" and d["checker"] == x_user:
            out.append({"app": app_id, "institution": a["institution"], "type": "CONFIRM_DECISION", "title": "Decision awaiting your confirmation",
                        "severity": "HIGH", "message": f"{d['maker']} proposes: {d['outcome'].replace('_', ' ').lower()}. {d['reason']}"})
        for r in s["records"].values():
            if r["app"] == app_id and r.get("watch") and x_role == "approver":
                out.append({"app": app_id, "institution": a["institution"], "type": "WATCH", "title": "Issuer changed a certificate after approval",
                            "severity": "HIGH", "message": r["watch"][-1]["note"]})
        if x_role == "approver" and run["outcome"] == "RECOMMEND_INSPECTION" and app_id not in s["decisions"]:
            out.append({"app": app_id, "institution": a["institution"], "type": "INSPECTION_RECOMMENDED", "title": "Inspection recommended",
                        "severity": "HIGH", "message": "Awaiting your decision"})
    return out


class Sources(BaseModel):
    down: list[str]


@app.get("/api/sources")
def get_sources():
    return {"down": sorted(checks.DOWN)}


@app.post("/api/sources")
def set_sources(body: Sources, x_role: str = Header("")):
    if x_role not in OFFICERS:
        raise HTTPException(403, "Officers only")
    checks.DOWN.clear()
    checks.DOWN.update(x for x in body.down if x in ("fire", "digilocker", "payments"))
    audit("admin", "SOURCE_STATUS", {"down": sorted(checks.DOWN)})
    return get_sources()


@app.get("/api/rules")
def get_rules():
    return {"rules": json.loads(checks.RULES_FILE.read_text(encoding="utf-8")),
            "norms": json.loads(checks.NORMS_FILE.read_text(encoding="utf-8")),
            "escalation": json.loads(checks.ESCALATION_FILE.read_text(encoding="utf-8"))}


@app.put("/api/rules/norms")
def put_norms(body: dict, x_role: str = Header(""), x_user: str = Header("")):
    if x_role != "approver":
        raise HTTPException(403, "Only the rules admin / approver can publish rules")
    try:
        checks.zen.ZenEngine().create_decision(json.dumps(body)).evaluate({"programme_level": "UG Engineering"})
    except Exception as e:
        raise HTTPException(422, f"Not a valid GoRules JDM decision: {e}")
    checks.NORMS_FILE.write_text(json.dumps(body, indent=2, ensure_ascii=False), encoding="utf-8")
    rules = json.loads(checks.RULES_FILE.read_text(encoding="utf-8"))
    major, minor = rules["version"].rsplit("/v", 1)
    rules["version"] = f"{major}/v{int(minor) + 1}"
    checks.RULES_FILE.write_text(json.dumps(rules, indent=2, ensure_ascii=False), encoding="utf-8")
    audit(f"approver:{x_user}", "RULES_PUBLISHED", {"version": rules["version"], "norms": body["nodes"][1]["content"]["rules"]})
    return {"ok": True, "version": rules["version"]}


# ---------- public: anyone can check an approval, no role needed ----------

PUBLIC = ("id", "institution", "aicte_id", "category", "intake", "cycle", "decided_at", "rules_version", "proof_score",
          "independent_pct", "proof_counts", "claims", "issued_at", "watch")


def public_record(rid):
    r = load()["records"].get(rid)
    if not r:
        raise HTTPException(404, "No such record in the AICTE register")
    return r


@app.get("/api/public/records")
def public_records(q: str = ""):
    q = q.strip().lower()
    return [{k: r[k] for k in PUBLIC} for r in load()["records"].values()
            if q in r["institution"].lower() or q in r["aicte_id"].lower()]


@app.get("/api/public/records/{rid}")
def public_record_detail(rid: str):
    return {k: public_record(rid)[k] for k in PUBLIC}


@app.get("/api/public/records/{rid}/pdf")
def public_record_pdf(rid: str):
    public_record(rid)
    return Response(records.pdf(rid), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{rid}.pdf"'})


@app.get("/api/public/records/{rid}/preview")
def public_record_preview(rid: str):
    public_record(rid)
    return Response(records.preview(records.pdf(rid)), media_type="image/png")


@app.post("/api/public/verify")
def public_verify(file: UploadFile = File(...)):  # sync: pyHanko's validator runs its own event loop
    data = file.file.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD or not data.startswith(b"%PDF"):
        raise HTTPException(422, "Upload the approval record PDF (at most 20 MB)")
    try:
        r = records.verify(data, load()["records"])
    except Exception as e:  # trust boundary: a malformed upload must not crash the public page
        raise HTTPException(422, f"Could not read this PDF: {str(e)[:120]}")
    r["preview"] = base64.b64encode(records.preview(data)).decode()
    if r["record"]:
        r["record"] = {k: r["record"][k] for k in PUBLIC}
    return r


ANY_PROGRAMME = "Any other programme"  # the table's catch-all row has an empty programme level


def norms_table():
    jdm = json.loads(checks.NORMS_FILE.read_text(encoding="utf-8"))
    return next(n for n in jdm["nodes"] if n["type"] == "decisionTableNode")["content"]


@app.get("/api/rules/norms/export")
def export_norms():
    """The norms table as plain JSON rows: the same format the import accepts."""
    t = norms_table()
    rows = [{t["inputs"][0]["name"]: r["i0"].strip('"') or ANY_PROGRAMME, **{o["name"]: int(float(r[o["id"]])) if float(r[o["id"]]).is_integer()
                                                                   else float(r[o["id"]]) for o in t["outputs"]}}
            for r in t["rules"]]
    return Response(json.dumps(rows, indent=2, ensure_ascii=False), media_type="application/json",
                    headers={"Content-Disposition": 'attachment; filename="pramaan-norms.json"'})


def pdf_rows(data):
    """A norms circular: 'Programme level: X' starts a row; the 'Name: value' lines after it fill that row."""
    rows = []
    for line in "\n".join(page.get_text() for page in pymupdf.open(stream=data)).splitlines():
        k, sep, v = line.partition(":")
        if not sep:
            continue
        if checks.squash(k) == "programmelevel":
            rows.append({"Programme level": v.strip()})
        elif rows:
            rows[-1][k.strip()] = v.strip()
    return rows


@app.post("/api/rules/norms/import")
def import_norms(file: UploadFile = File(...), x_role: str = Header("")):
    """Read norms from a circular (PDF) or a JSON export. Returns the proposed values; nothing is published here."""
    if x_role != "approver":
        raise HTTPException(403, "Only the rules admin / approver can change rules")
    data = file.file.read(MAX_UPLOAD + 1)
    try:
        rows = pdf_rows(data) if data.startswith(b"%PDF") else json.loads(data)
        assert isinstance(rows, list) and rows and all(isinstance(r, dict) for r in rows)
    except Exception:
        raise HTTPException(422, "Upload a norms circular (PDF) or a norms JSON exported from this page")
    t = norms_table()
    cols = {checks.squash(o["name"]): o for o in t["outputs"]}
    have = {r["i0"].strip('"') or ANY_PROGRAMME: r for r in t["rules"]}
    proposed, changes = [], []
    for row in rows:
        programme = str(next((v for k, v in row.items() if checks.squash(k) == "programmelevel"), ""))
        if programme not in have:
            raise HTTPException(422, f"Unknown programme level '{programme}'. Known: {', '.join(have)}")
        values = {}
        for k, v in row.items():
            if checks.squash(k) == "programmelevel":
                continue
            o = cols.get(checks.squash(k))
            if not o:
                raise HTTPException(422, f"Unknown norm '{k}'. Known: {', '.join(c['name'] for c in t['outputs'])}")
            try:
                n = float(str(v).split()[0])
                assert n > 0
            except Exception:
                raise HTTPException(422, f"'{k}' for {programme} must be a positive number, got '{v}'")
            values[o["id"]] = f"{n:g}"
            if values[o["id"]] != have[programme][o["id"]]:
                changes.append({"programme": programme, "norm": o["name"], "from": have[programme][o["id"]], "to": values[o["id"]]})
        proposed.append({"programme": "" if programme == ANY_PROGRAMME else programme, "values": values})
    return {"rows": proposed, "changes": changes, "source": "PDF" if data.startswith(b"%PDF") else "JSON"}


@app.get("/api/audit")
def get_audit(x_role: str = Header("")):
    if x_role not in OFFICERS | {"auditor"}:
        raise HTTPException(403, "Officers and auditors only")
    lines = AUDIT.read_text().splitlines() if AUDIT.exists() else []
    return {"chain": verify_chain(), "entries": [json.loads(x) for x in lines][-200:]}


app.mount("/", StaticFiles(directory=checks.BASE / "static", html=True), name="static")
