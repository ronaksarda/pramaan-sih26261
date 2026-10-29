"""Pramaan check engine: extract fields, apply rules, verify with sources, analyse photos, escalate.

Every finding carries its rule, clause and evidence. The engine only produces findings and a
recommendation; it never records a decision.
"""
import base64
import hashlib
import io
import json
import logging
import math
import os
import re
import time
import uuid
from datetime import date, datetime, timedelta
from pathlib import Path

import imagehash
import numpy as np
import pymupdf
import zen
from PIL import Image, ImageChops, ImageFilter
from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
from rapidfuzz import fuzz

import storage

os.environ.setdefault("HF_HUB_OFFLINE", "1")  # models are cached locally; never call the hub during checks
BASE = Path(__file__).parent
DATA = storage.DATA
RULES_FILE = BASE / "rules.json"
NORMS_FILE = BASE / "rules" / "norms.jdm.json"
ESCALATION_FILE = BASE / "rules" / "escalation.jdm.json"
WEIGHT = {"HIGH": 15, "MEDIUM": 6, "LOW": 1}
ELA_THRESHOLD = 13  # peak of the blurred error-level map; clean synthetic scans peak at 8-9, edited ones at 17-18
logging.getLogger("pyhanko").setLevel(logging.CRITICAL)  # its diff analyser logs a traceback for edited files; we report it as a finding

# shortcut: mock registries are local lookups with a down switch; swap for API Setu / state portals after onboarding.
DOWN = set()


OCR_CONFUSABLE = str.maketrans("OILSBZ", "011582")


def registry_lookup(source, key):
    """Exact key first, then tolerant of common OCR confusions (O/0, I/1, S/5 ...)."""
    if source in DOWN:
        raise ConnectionError(f"{source} registry unreachable")
    table = json.loads((DATA / "registry.json").read_text())[source]
    canon = lambda s: re.sub(r"[^A-Z0-9]", "", s.upper()).translate(OCR_CONFUSABLE)
    return table.get(key) or next((v for k, v in table.items() if canon(k) == canon(key)), None)


def zen_eval(path, data):
    return zen.ZenEngine().create_decision(path.read_text(encoding="utf-8")).evaluate(data)["result"]


def parse_date(s):
    return datetime.strptime(s.strip(), "%d-%m-%Y").date()


# ---------- extraction ----------

_ocr = None


def ocr(img):
    global _ocr
    if _ocr is None:
        from rapidocr_onnxruntime import RapidOCR
        _ocr = RapidOCR()
    return _ocr(np.asarray(img))[0] or []


def squash(s):
    return re.sub(r"[^a-z0-9]", "", s.lower())


def llm_fields(jpeg, doc, wanted):
    """Vision-LLM fallback for fields OCR missed or read with low confidence. Needs GROQ_API_KEY."""
    from groq import Groq
    prompt = (f"This is a scanned Indian {doc.replace('_', ' ').removesuffix('.pdf')}. Return only JSON with these keys, "
              f"copying values exactly as printed (null if absent): {wanted}")
    r = Groq().chat.completions.create(
        model=os.environ.get("GROQ_VISION_MODEL", "meta-llama/llama-4-scout-17b-16e-instruct"),
        response_format={"type": "json_object"}, temperature=0,
        messages=[{"role": "user", "content": [
            {"type": "text", "text": prompt},
            {"type": "image_url", "image_url": {"url": "data:image/jpeg;base64," + base64.b64encode(jpeg).decode()}}]}])
    return {k: v for k, v in json.loads(r.choices[0].message.content).items() if k in wanted and v}


def extract(data, doc, wanted):
    """Text layer first; scanned pages go through OCR, then the vision LLM for anything still missing."""
    pdf = pymupdf.open(stream=data)
    page = pdf[0]
    out = {"fields": {}, "boxes": {}, "conf": {}, "method": "Read from the PDF's text", "jpeg": None}
    text = page.get_text()
    if len(text.strip()) > 20:
        for line in text.splitlines():
            m = re.match(r"^([^:]{2,40}):\s*(.+)$", line.strip())
            if m:
                k, v = m.group(1).strip(), m.group(2).strip()
                out["fields"][k] = v  # later lines win, as a reader of the page would see
                out["conf"][k] = 1.0
        for k, v in out["fields"].items():
            hits = page.search_for(f"{k}: {v}")
            if hits:
                out["boxes"][k] = [round(c, 1) for c in hits[-1]]
        return out
    jpeg = pdf.extract_image(page.get_images()[0][0])["image"]
    img = Image.open(io.BytesIO(jpeg)).convert("RGB")
    scale = page.rect.width / img.width
    out.update(method="Read from the scanned image (text recognition)", jpeg=jpeg)
    keys = {squash(w): w for w in wanted}
    for box, txt, score in ocr(img):
        if ":" not in txt:
            continue
        label, value = txt.split(":", 1)
        key = keys.get(squash(label))
        if key:
            xs, ys = [p[0] for p in box], [p[1] for p in box]
            out["fields"][key] = value.strip()
            out["conf"][key] = round(float(score), 2)
            out["boxes"][key] = [round(min(xs) * scale - 3, 1), round(min(ys) * scale - 3, 1),
                                 round(max(xs) * scale + 3, 1), round(max(ys) * scale + 3, 1)]
    weak = [w for w in wanted if out["conf"].get(w, 0) < 0.8]
    if weak and os.environ.get("GROQ_API_KEY"):
        try:
            for k, v in llm_fields(jpeg, doc, weak).items():
                out["fields"][k], out["conf"][k] = str(v), 0.8
            out["method"] += ", unclear details read by an AI model"
        except Exception as e:  # the LLM is a fallback: a failure leaves the field for the officer's micro-task
            out["llm_error"] = str(e)[:200]
    return out


# ---------- matching ----------

ABBR = {"engg": "engineering", "inst": "institute", "shri": "sri", "sree": "sri", "tech": "technology", "coll": "college"}


def norm(s):
    return "".join(ABBR.get(w, w) for w in re.sub(r"[^a-z ]", " ", s.lower()).split())


def similarity(a, b):
    """Spaces removed on purpose: OCR often drops them."""
    return round(fuzz.ratio(norm(a), norm(b)))


def metres(a, b):
    la1, lo1, la2, lo2 = map(math.radians, (*a, *b))
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 2 * 6371000 * math.asin(math.sqrt(h))


# ---------- integrity ----------

def validate_dsc(data):
    vc = ValidationContext(trust_roots=[load_cert_from_pemder(str(DATA / "pki" / "ca.pem"))], allow_fetching=False)
    r = PdfFileReader(io.BytesIO(data))
    if not r.embedded_signatures:
        return None
    st = validate_pdf_signature(r.embedded_signatures[0], vc)
    return {"intact": st.intact, "valid": st.valid, "trusted": st.trusted, "coverage": st.coverage.name,
            "cert_sha256": hashlib.sha256(st.signing_cert.dump()).hexdigest(),
            "modification_level": st.modification_level.name if st.modification_level else None,
            "docmdp_ok": st.docmdp_ok, "signer": st.signing_cert.subject.human_friendly,
            "revisions": r.xrefs.total_revisions}


def revisions(data):
    """Byte offsets where each saved version of a PDF ends. Every prefix up to an %%EOF is a complete earlier version."""
    ends, i = [], 0
    while (i := data.find(b"%%EOF", i)) != -1:
        i += 5
        while i < len(data) and data[i:i + 1] in b"\r\n":
            i += 1
        ends.append(i)
    return ends or [len(data)]


def revision_lines(data, end):
    return [ln.strip() for ln in pymupdf.open(stream=data[:end])[0].get_text().splitlines() if ln.strip()]


def covered_values(data):
    """Text that an annotation box sits on top of: the reader sees the box, the file still holds the original value."""
    page = pymupdf.open(stream=data)[0]
    words = page.get_text("words")
    out = []
    for annot in page.annots() or []:
        r = annot.rect
        hidden = [w[4] for w in words if (pymupdf.Rect(w[:4]) & r).get_area() > 0.5 * pymupdf.Rect(w[:4]).get_area()]
        if hidden:
            out.append({"bbox": [round(v, 1) for v in r], "hidden": " ".join(hidden), "shown": (annot.info.get("content") or "").strip()})
    return out


def ela_map(jpeg):
    """Error level analysis: re-save at quality 90 and look at where the error is unusually high."""
    img = Image.open(io.BytesIO(jpeg)).convert("RGB")
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=90)
    diff = np.asarray(ImageChops.difference(img, Image.open(buf)).convert("L"), dtype=np.float32)
    return np.asarray(Image.fromarray(np.clip(diff * 8, 0, 255).astype(np.uint8)).filter(ImageFilter.BoxBlur(10)),
                      dtype=np.float32), img


def ela_check(jpeg, page_width):
    heat, img = ela_map(jpeg)
    peak = float(heat.max())
    ys, xs = np.where(heat > 0.6 * peak)
    s = page_width / img.width
    return peak, [round(float(v) * s, 1) for v in (xs.min(), ys.min(), xs.max(), ys.max())]


# ---------- photos ----------

_clip = _dino = None
SCENES = {"lab": "a computer lab with desktop computers", "classroom": "a classroom with desks and a blackboard",
          "library": "a library with bookshelves", "outdoor": "an outdoor campus"}


def clip_scene(img):
    global _clip
    import open_clip
    import torch
    if _clip is None:
        model, _, pre = open_clip.create_model_and_transforms("ViT-B-32", pretrained="laion2b_s34b_b79k")
        tok = open_clip.get_tokenizer("ViT-B-32")
        with torch.no_grad():
            t = model.eval().encode_text(tok(list(SCENES.values())))
        _clip = (model, pre, t / t.norm(dim=-1, keepdim=True))
    model, pre, text = _clip
    with torch.no_grad():
        i = model.encode_image(pre(img).unsqueeze(0))
        probs = (100 * (i / i.norm(dim=-1, keepdim=True)) @ text.T).softmax(-1)[0].tolist()
    return dict(zip(SCENES, [round(p, 3) for p in probs]))


def dino_monitors(img):
    global _dino
    import torch
    from transformers import AutoModelForZeroShotObjectDetection, AutoProcessor
    if _dino is None:
        name = "IDEA-Research/grounding-dino-tiny"
        _dino = (AutoProcessor.from_pretrained(name), AutoModelForZeroShotObjectDetection.from_pretrained(name).eval())
    proc, model = _dino
    inp = proc(images=img, text="a computer monitor.", return_tensors="pt")
    with torch.no_grad():
        out = model(**inp)
    r = proc.post_process_grounded_object_detection(out, inp.input_ids, threshold=0.35, text_threshold=0.3,
                                                    target_sizes=[img.size[::-1]])[0]
    return [[round(float(v), 1) for v in b] for b in r["boxes"]]


def photo_meta(img):
    ex = img.getexif()
    gps = ex.get_ifd(0x8825)
    to_deg = lambda t: float(t[0]) + float(t[1]) / 60 + float(t[2]) / 3600
    loc = (to_deg(gps[2]), to_deg(gps[4])) if 2 in gps and 4 in gps else None
    taken = datetime.strptime(ex[0x0132], "%Y:%m:%d %H:%M:%S").date() if 0x0132 in ex else None
    return loc, taken


def analyse_photo(data, label):
    """CLIP scene + Grounding DINO monitor count, cached by content hash (CPU inference takes ~15 s)."""
    cache_file = Path(os.environ.get("PRAMAAN_CV_CACHE", BASE / ".cv_cache.json"))  # content-hash keyed: survives regeneration
    cache = json.loads(cache_file.read_text()) if cache_file.exists() else {}
    key = hashlib.sha256(data).hexdigest() + ":" + label
    if key not in cache:
        img = Image.open(io.BytesIO(data)).convert("RGB")
        cache[key] = {"scene": clip_scene(img), "monitors": dino_monitors(img) if label == "lab" else None}
        cache_file.write_text(json.dumps(cache))
    return cache[key]


_peers = {}  # (path, mtime) -> (sha256, land survey no); files rarely change, so the national index stays cheap


def peer_files(app_id):
    """Every other application's document hashes and land survey numbers: what only the regulator can compare."""
    out = []
    for app_file in sorted((DATA / "apps").glob("*/application.json")):
        other = json.loads(app_file.read_text())
        if other["id"] == app_id:
            continue
        for pdf in app_file.parent.glob("*.pdf"):
            key = (str(pdf), pdf.stat().st_mtime_ns)
            if key not in _peers:
                data = storage.read(pdf)
                survey = None
                if pdf.name == "occupancy_certificate.pdf":
                    m = re.search(r"Land Survey No:\s*(\S+)", pymupdf.open(stream=data)[0].get_text())
                    survey = m and m.group(1)
                _peers[key] = (hashlib.sha256(data).hexdigest(), survey)
            sha, survey = _peers[key]
            out.append({"app": other["id"], "aicte_id": other["aicte_id"], "institution": other["institution"],
                        "doc": pdf.name, "sha": sha, "survey": survey})
    return out


def earlier_photo_hashes(submitted_at):
    """Photos from applications submitted before this one: the later copy is the one flagged."""
    out = []
    for app_file in sorted((DATA / "apps").glob("*/application.json")):
        other = json.loads(app_file.read_text())
        if other["submitted_at"] < submitted_at:
            for p in other["photos"]:
                img = Image.open(io.BytesIO(storage.read(app_file.parent / p["file"])))
                out.append((other["id"], p["file"], imagehash.phash(img)))
    return out


# ---------- run ----------

def run(app_id):
    t0 = time.time()
    rules = json.loads(RULES_FILE.read_text(encoding="utf-8"))  # re-read every run so rule edits apply immediately
    norms = rules["norms"]
    folder = DATA / "apps" / app_id
    app = json.loads((folder / "application.json").read_text())
    master = json.loads((DATA / "master.json").read_text())[app["aicte_id"]]
    table = zen_eval(NORMS_FILE, {"programme_level": app["programme_level"]})
    app_date = date.fromisoformat(app["application_date"])
    findings, verifications, photos, extraction = [], [], [], {}

    def flag(check, message, evidence=(), clause=None, **extra):
        r = rules["checks"][check]
        findings.append({"id": len(findings), "check": check, "title": r["title"], "severity": extra.pop("severity", r["severity"]),
                         "action": r["action"], "clause": clause or r["clause"], "message": message,
                         "evidence": list(evidence), "status": "OPEN", **extra})

    def ev(doc, field):
        return {"kind": "pdf", "app": app_id, "doc": doc, "bbox": extracted[doc]["boxes"].get(field)}

    # 1. completeness + extraction
    required = rules["categories"][app["category"]]["required"]
    blobs, extracted = {}, {}
    for doc, clause in required.items():
        if not (folder / doc).exists():
            flag("DOC_MISSING", f"Mandatory document missing: {doc}", clause=clause, doc=doc)
            continue
        blobs[doc] = storage.read(folder / doc)
        wanted = rules["required_fields"].get(doc, [])
        extracted[doc] = extract(blobs[doc], doc, wanted)
        x = extracted[doc]
        extraction[doc] = {"method": x["method"], "fields": x["fields"], "conf": x["conf"]}
        for field in wanted:
            if field not in x["fields"]:
                flag("FIELD_MISSING", f"{doc}: field '{field}' could not be read", [ev(doc, field)])
            elif x["conf"].get(field, 1) < 0.8:
                flag("FIELD_LOW_CONFIDENCE", f"{doc}: '{field}' read as '{x['fields'][field]}' with confidence "
                     f"{x['conf'][field]}; officer to confirm", [ev(doc, field)])
    docs = {k: v["fields"] for k, v in extracted.items()}

    # 2. validity of what the document itself says
    for doc, field in rules["expiry_fields"].items():
        if field in docs.get(doc, {}):
            valid = parse_date(docs[doc][field])
            if valid < app_date:
                flag("DOC_EXPIRED", f"{doc} expired {(app_date - valid).days} days before the application date",
                     [ev(doc, field)])
            elif valid < app_date + timedelta(days=norms["expiry_warn_days"]):
                flag("DOC_EXPIRING", f"{doc} expires in {(valid - app_date).days} days", [ev(doc, field)])

    # 3. consistency against the AICTE master record and history
    for doc, f in docs.items():
        if "Institution Name" in f:
            s = similarity(f["Institution Name"], master["name"])
            if s < norms["name_match_ok"]:
                flag("NAME_MISMATCH", f"{doc}: '{f['Institution Name']}' vs AICTE record '{master['name']}' "
                     f"(similarity {s}%)", [ev(doc, "Institution Name")],
                     severity="HIGH" if s < norms["name_match_review"] else "MEDIUM")
        if "AICTE Permanent ID" in f and f["AICTE Permanent ID"] != app["aicte_id"]:
            flag("ID_MISMATCH", f"{doc}: AICTE ID {f['AICTE Permanent ID']} vs application {app['aicte_id']}",
                 [ev(doc, "AICTE Permanent ID")])
    aff = docs.get("affidavit.pdf", {})
    if "Signatory" in aff and similarity(aff["Signatory"], master["signatory"]) < norms["name_match_review"]:
        flag("SIGNATORY_MISMATCH", f"Affidavit signed by '{aff['Signatory']}'; authorised signatory on record is "
             f"'{master['signatory']}'", [ev("affidavit.pdf", "Signatory")])
    if {"E-Stamp Date", "Affidavit Date"} <= aff.keys() and parse_date(aff["Affidavit Date"]) < parse_date(aff["E-Stamp Date"]):
        flag("DATE_ILLOGICAL", "Affidavit dated before its e-stamp paper", [ev("affidavit.pdf", "Affidavit Date")])

    # 4. integrity: DSC (real cryptographic check), scan tampering, duplicate photos
    if "affidavit.pdf" in blobs:
        sig = validate_dsc(blobs["affidavit.pdf"])
        e = [{"kind": "pdf", "app": app_id, "doc": "affidavit.pdf", "bbox": None}]
        if sig is None:
            flag("DSC_MISSING", "Affidavit is not digitally signed", e)
            status = "MISMATCH"
        elif not (sig["intact"] and sig["valid"]):
            flag("DSC_INVALID", "Digital signature is broken or invalid", e)
            status = "MISMATCH"
        elif sig["coverage"] != "ENTIRE_FILE" or not sig["docmdp_ok"]:
            flag("EDITED_AFTER_SIGNING", f"The affidavit was changed after it was digitally signed: the file holds "
                 f"{sig['revisions']} versions. Verification required.", e)
            status = "MISMATCH"
        else:
            status = "VERIFIED" if sig["trusted"] else "MANUAL_REVIEW"
        verifications.append(_ver("affidavit.pdf", "Digital signature check", status, sig,
                                  ["signature", "certificate chain", "coverage"]))
    for doc, blob in blobs.items():
        for c in covered_values(blob):
            flag("VALUE_COVERED", f"{doc}: an annotation box covers '{c['hidden']}'"
                 + (f" and shows '{c['shown']}' on top" if c["shown"] else "") + ". The file still holds the covered value. Verification required.",
                 [{"kind": "pdf", "app": app_id, "doc": doc, "bbox": c["bbox"]}])
        if len(revisions(blob)) > 1:
            extraction[doc]["revisions"] = len(revisions(blob))
    for doc, x in extracted.items():
        if x["jpeg"]:
            peak, box = ela_check(x["jpeg"], pymupdf.open(stream=blobs[doc])[0].rect.width)
            extraction[doc]["ela_peak"] = round(peak, 1)
            if peak >= ELA_THRESHOLD:
                flag("SCAN_TAMPER", f"{doc}: one area of this scan was changed after scanning; it is highlighted in red "
                     f"(edit signal {peak:.0f}, clean scans stay below {ELA_THRESHOLD}). Verification required.",
                     [{"kind": "ela", "app": app_id, "doc": doc, "bbox": box}])

    hashes = earlier_photo_hashes(app["submitted_at"])
    site = (master["lat"], master["lng"])
    for p in app["photos"]:
        data = storage.read(folder / p["file"])
        img = Image.open(io.BytesIO(data))
        mine = imagehash.phash(img)
        for other_app, other_file, h in hashes:
            if mine - h <= norms["phash_max_distance"]:
                flag("DUPLICATE_PHOTO", f"This '{p['label']}' photo is the same picture as {other_app}/{other_file}, "
                     "submitted earlier by another college (resized or re-saved copy)",
                     [{"kind": "img", "app": app_id, "doc": p["file"]}, {"kind": "img", "app": other_app, "doc": other_file}],
                     links=[{"app": other_app, "kind": "photo"}])

        # 5. infrastructure evidence
        loc, taken = photo_meta(img)
        cv = analyse_photo(data, p["label"])
        scene = max(cv["scene"], key=cv["scene"].get)
        info = {"file": p["file"], "label": p["label"], "scene": scene, "scene_p": cv["scene"][scene],
                "monitors": None if cv["monitors"] is None else len(cv["monitors"]),
                "distance_m": None if loc is None else round(metres(loc, site))}
        photos.append(info)
        e = [{"kind": "img", "app": app_id, "doc": p["file"]}]
        if loc is None:
            flag("GPS_MISSING", f"'{p['label']}' photo has no GPS location", e)
        elif info["distance_m"] > norms["photo_geofence_m"]:
            flag("GPS_FAR", f"'{p['label']}' photo taken {info['distance_m'] / 1000:.1f} km from the declared campus "
                 "entrance", e, severity="HIGH" if info["distance_m"] > norms["photo_geofence_high_m"] else "MEDIUM")
        if taken and (app_date - taken).days > norms["photo_max_age_days"]:
            flag("PHOTO_STALE", f"'{p['label']}' photo is {(app_date - taken).days} days old", e)
        enough_monitors = p["label"] == "lab" and info["monitors"] >= table["lab_min_monitors_visible"]
        if scene != p["label"] and info["scene_p"] >= norms["scene_min_confidence"] and not enough_monitors:  # detector beats CLIP
            flag("SCENE_MISMATCH", f"Photo declared as '{p['label']}' looks like a {scene} "
                 f"({info['scene_p']:.0%} sure)", e)
        if p["label"] == "lab" and info["monitors"] < table["lab_min_monitors_visible"]:
            flag("EQUIPMENT_LOW", f"Lab photo shows {info['monitors']} computer monitor{'' if info['monitors'] == 1 else 's'}; at least "
                 f"{table['lab_min_monitors_visible']} expected", [{**e[0], "kind": "boxes", "boxes": cv["monitors"]}])
    for i, area in enumerate(app["classroom_areas_sqm"], 1):
        if area < table["classroom_min_sqm"]:
            flag("AREA_SHORTFALL", f"Classroom {i}: {area} m² declared vs {table['classroom_min_sqm']} m² norm")
    # faculty: the same person (salted PAN hash) on another institution's list this cycle, from the AICTE faculty registry
    faculty_registry = json.loads((DATA / "registry.json").read_text())["faculty"]
    roster = app.get("faculty_roster", [])  # webhook drafts have no roster yet
    ghosts = [(f, [o for o in faculty_registry.get(f["pan_hash"], []) if o["aicte_id"] != app["aicte_id"]]) for f in roster]
    ghosts = [(f, o) for f, o in ghosts if o]
    if ghosts:
        where = sorted({o["institution"] for _, others in ghosts for o in others})
        flag("GHOST_FACULTY", f"{len(ghosts)} of {len(roster)} declared faculty are also on the 2026-27 faculty list of "
             f"{', '.join(where)} (PAN match): {', '.join(f['name'] + ' (' + f['pan_masked'] + ')' for f, _ in ghosts[:4])}"
             f"{' and more' if len(ghosts) > 4 else ''}. Effective faculty strength: {len(roster) - len(ghosts)}.",
             links=[{"institution": w, "kind": "faculty", "count": sum(w in {o["institution"] for o in others} for _, others in ghosts)}
                    for w in where])
    students = app["proposed_intake"] * norms["programme_years"]
    ratio = students / app["faculty_count"]
    if ratio > table["faculty_ratio_max"]:
        flag("FACULTY_RATIO", f"Faculty-student ratio 1:{ratio:.0f} ({app['faculty_count']} faculty for {students} "
             f"students) vs 1:{table['faculty_ratio_max']} norm")
    if app["building_age_years"] > norms["structural_certificate_after_years"]:
        flag("STRUCTURAL_REQUIRED", "Building older than 30 years: Structural Stability Certificate required")
    # what changed since the last approval: growth in intake must be matched by growth in what supports it
    last, changes = master.get("last_approval"), None  # a first-time applicant has no previous cycle
    if last:
        oc = docs.get("occupancy_certificate.pdf", {})
        now = {"intake": app["proposed_intake"], "faculty": app["faculty_count"], "classrooms": len(app["classroom_areas_sqm"]),
               "built_up_sqm": int(oc["Built-up Area (sq m)"]) if "Built-up Area (sq m)" in oc else None}
        pct = lambda a, b: None if a is None else round(100 * (a - b) / b)
        changes = {"cycle": last["cycle"], "rows": [{"field": k, "then": last[k], "now": v, "pct": pct(v, last[k])}
                                                    for k, v in now.items()]}
        growth = pct(now["intake"], last["intake"])
        behind = [c for c in changes["rows"][1:] if c["pct"] is not None and c["pct"] < growth / 2]
        if growth >= norms["intake_jump_pct"] and behind:
            flag("UNSUPPORTED_GROWTH", f"Intake {last['intake']} → {now['intake']} (+{growth}%) since {last['cycle']}, but "
                 + "; ".join(f"{CHANGE_LABEL[c['field']]} {c['then']} → {c['now']} ({c['pct']:+d}%)" for c in behind)
                 + ". Evidence of the added capacity is needed.")
    for past in master.get("past_deficiencies", []):
        if any(f["check"] == past for f in findings):
            flag("REPEAT_DEFICIENCY", f"{past.replace('_', ' ').title()} was also recorded in the previous approval cycle")

    # cross-college: the same file or the same land in another college's application
    peers = peer_files(app_id)
    for doc, blob in blobs.items():
        sha = hashlib.sha256(blob).hexdigest()
        for o in peers:
            if o["sha"] == sha and o["aicte_id"] != app["aicte_id"]:
                flag("IDENTICAL_FILE", f"{doc} is byte-for-byte the same file that {o['institution']} ({o['app']}) submitted as "
                     f"{o['doc']}. One certificate cannot belong to two colleges.",
                     [{"kind": "pdf", "app": app_id, "doc": doc, "bbox": None}, {"kind": "pdf", "app": o["app"], "doc": o["doc"], "bbox": None}],
                     links=[{"app": o["app"], "kind": "file"}])
    survey = docs.get("occupancy_certificate.pdf", {}).get("Land Survey No")
    for o in peers:
        if survey and o["survey"] == survey and o["aicte_id"] != app["aicte_id"]:
            flag("LAND_REUSED", f"Land survey no. {survey} on this occupancy certificate is also shown by {o['institution']} "
                 f"({o['app']}). The same land cannot meet two colleges' land requirement.",
                 [ev("occupancy_certificate.pdf", "Land Survey No"), {"kind": "pdf", "app": o["app"], "doc": o["doc"], "bbox": None}],
                 links=[{"app": o["app"], "kind": "land"}])

    # 6. issuing-authority verification
    def source(doc, name, registry, key_field, compare):
        if doc not in docs or key_field not in docs[doc]:
            return
        key = docs[doc][key_field]
        record, err = None, None
        for _ in range(norms["source_retries"]):
            try:
                record, err = registry_lookup(registry, key), None
                break
            except ConnectionError as e:
                err = str(e)
        if err:
            flag("SOURCE_DOWN", f"{name} did not answer after {norms['source_retries']} tries; "
                 "moves to manual review if it stays offline", [ev(doc, key_field)])
            verifications.append(_ver(doc, name, "SOURCE_UNAVAILABLE", {"error": err}, [key_field]))
            return
        status, diff, field = compare(record)
        if status in ("MISMATCH", "EXPIRED") and diff:
            flag("SOURCE_MISMATCH", f"{doc}: {name} {diff}", [ev(doc, field or key_field)])
        verifications.append(_ver(doc, name, status, record, [key_field] + ([field] if field else [])))

    def fire_cmp(rec):
        if rec is None:
            return "MISMATCH", "has no record of this NOC", None
        if rec.get("revoked"):
            return "MISMATCH", f"revoked this NOC on {rec['revoked']}", None
        shown = docs["fire_noc.pdf"].get("Valid Upto", "")
        if shown and squash(shown) != squash(rec["valid_upto"]):
            status = "EXPIRED" if parse_date(rec["valid_upto"]) < app_date else "MISMATCH"
            return status, f"says valid until {rec['valid_upto']}; the document shows {shown}", "Valid Upto"
        return ("EXPIRED", "", None) if parse_date(rec["valid_upto"]) < app_date else ("VERIFIED", "", None)

    def digilocker_cmp(rec):
        if rec is None:
            return "MISMATCH", "has no issued document at this URI", None
        same = rec["sha256"] == hashlib.sha256(blobs["occupancy_certificate.pdf"]).hexdigest()
        return ("VERIFIED", "", None) if same else ("MISMATCH", "issued copy differs from the upload", None)

    source("fire_noc.pdf", "State fire department records (demo copy)", "fire", "NOC No", fire_cmp)
    source("occupancy_certificate.pdf", "DigiLocker (demo copy)", "digilocker", "DigiLocker URI", digilocker_cmp)
    source("fee_receipt.pdf", "AICTE payment records (demo copy)", "payments", "Transaction ID",
           lambda r: ("VERIFIED", "", None) if r and r["aicte_id"] == app["aicte_id"] else ("MISMATCH", "does not match", None))
    if "satellite_map.pdf" in docs:
        m = docs["satellite_map.pdf"]
        dist = metres((float(m["Latitude"]), float(m["Longitude"])), site)
        verifications.append(_ver("satellite_map.pdf", "AICTE institution records", "VERIFIED" if dist <= norms["map_match_m"]
                                  else "MISMATCH", {"distance_m": round(dist)}, ["Latitude", "Longitude"]))
    for doc in ("audited_accounts.pdf", "university_noc.pdf"):
        if doc in docs:
            verifications.append(_ver(doc, "No online source", "MANUAL_REVIEW", None, []))

    # 7. escalation: GoRules ZEN decision table over open findings
    rect = app.get("rectification")
    correction = None
    if rect:  # a correction round: what was asked, what changed, and what changed without being asked
        snap = rect["snapshot"]
        now_hash = {k: hashlib.sha256(v).hexdigest() for k, v in blobs.items()}
        changed = sorted(d for d in set(now_hash) | set(snap["doc_hashes"]) if now_hash.get(d) != snap["doc_hashes"].get(d))
        asked = {it["doc"] for it in rect["items"] if it["doc"]}
        diffs = []
        for doc in changed:
            old, new = snap["fields"].get(doc, {}), docs.get(doc, {})
            diffs.append({"doc": doc, "asked": doc in asked,
                          "fields": [{"field": k, "old": old.get(k), "new": new.get(k)}
                                     for k in sorted(set(old) | set(new)) if old.get(k) != new.get(k)]})
        for d in diffs:
            if not d["asked"]:
                shown = "; ".join(f"{f['field']}: {f['old'] or '(none)'} -> {f['new'] or '(none)'}" for f in d["fields"][:3])
                flag("CHANGED_OUTSIDE_REQUEST", f"{d['doc']} was replaced in correction round {rect['round']} although the "
                     f"deficiency letter did not ask for it. {shown or 'File contents changed.'}",
                     [{"kind": "pdf", "app": app_id, "doc": d["doc"], "bbox": None}] if d["doc"] in blobs else [])
        still = {(f["check"], f.get("doc") or next((e["doc"] for e in f["evidence"] if e["app"] == app_id), "")) for f in findings}
        correction = {"round": rect["round"], "due": rect["due"], "changed": diffs,
                      "items": [{**it, "fixed": (it["check"], it["doc"]) not in still} for it in rect["items"]]}
    claims = proof_claims(app, required, findings, verifications, photos, ghosts, changes)
    levels = rules["proof_levels"]
    proof = {"score": round(100 * sum(levels[c["level"]]["weight"] for c in claims) / len(claims)),
             "independent_pct": round(100 * sum(c["level"] in ("ISSUER_CONFIRMED", "RECORD_MATCHED") for c in claims) / len(claims)),
             "counts": {k: sum(c["level"] == k for c in claims) for k in levels}, "claims": claims}
    counts = {a: sum(f["action"] == a for f in findings) for a in ("RECOMMEND_INSPECTION", "ADDITIONAL_EVIDENCE", "RECTIFY")}
    outcome = zen_eval(ESCALATION_FILE, counts)["outcome"]
    return {"app_id": app_id, "rules_version": rules["version"], "category_label": rules["categories"][app["category"]]["label"],
            "norms": table, "ran_at": datetime.now().isoformat(timespec="seconds"), "outcome": outcome,
            "risk_score": min(100, sum(WEIGHT[f["severity"]] for f in findings)),
            "findings": findings, "verifications": verifications, "photos": photos, "extraction": extraction,
            "proof": proof, "changes": changes, "correction": correction,
            "seconds": round(time.time() - t0, 1),
            "doc_hashes": {k: hashlib.sha256(v).hexdigest() for k, v in sorted(blobs.items())}}


CHANGE_LABEL = {"intake": "Intake", "faculty": "faculty", "classrooms": "classrooms", "built_up_sqm": "built-up area (m²)"}
DOC_LABEL = {"affidavit.pdf": "Affidavit", "fee_receipt.pdf": "Fee payment", "occupancy_certificate.pdf": "Occupancy certificate",
             "fire_noc.pdf": "Fire safety NOC", "satellite_map.pdf": "Campus location", "audited_accounts.pdf": "Audited accounts",
             "university_noc.pdf": "University NOC"}


TITLE = {k: v["title"] for k, v in json.loads(RULES_FILE.read_text(encoding="utf-8"))["checks"].items()}


def proof_claims(app, required, findings, verifications, photos, ghosts, changes):
    """How strongly each claim in the application is proven, from 'declared only' up to 'confirmed by the issuer'."""
    against = {}  # file -> first finding that contradicts it
    for f in findings:
        for e in f["evidence"]:
            if e["app"] == app["id"] and (f["severity"] == "HIGH" or e["doc"].startswith("photos/")):
                against.setdefault(e["doc"], f["check"])
    missing = {f["doc"] for f in findings if f["check"] == "DOC_MISSING"}
    ver = {v["doc"]: v for v in verifications}
    claims = []
    for doc in required:
        v = ver.get(doc)
        if doc in missing:
            level, basis = "DECLARED_ONLY", "Document not uploaded"
        elif doc in against:
            level, basis = "CONTRADICTED", TITLE[against[doc]]
        elif v and v["status"] == "VERIFIED":
            level = {"Digital": "SIGNED_INTACT", "AICTE": "RECORD_MATCHED"}.get(v["source"].split()[0], "ISSUER_CONFIRMED")
            basis = v["source"]
        elif v and v["status"] in ("MISMATCH", "EXPIRED"):
            level, basis = "CONTRADICTED", f"{v['source']}: {v['status'].lower()}"
        elif v and v["status"] == "SOURCE_UNAVAILABLE":
            level, basis = "EVIDENCE_ONLY", f"{v['source']} unreachable; re-check pending"
        else:
            level, basis = "EVIDENCE_ONLY", "Read and cross-checked; no online source"
        claims.append({"claim": DOC_LABEL.get(doc, doc), "level": level, "basis": basis})
    roster = app.get("faculty_roster", [])
    claims.append({"claim": f"Faculty strength ({app['faculty_count']})", **(
        {"level": "CONTRADICTED", "basis": f"{len(ghosts)} also on another institution's faculty list"} if ghosts else
        {"level": "RECORD_MATCHED", "basis": "PAN unique in AICTE faculty registry"} if roster else
        {"level": "DECLARED_ONLY", "basis": "No faculty list"})})
    intake = changes and changes["rows"][0]
    claims.append({"claim": f"Intake ({app['proposed_intake']})", **(
        {"level": "CONTRADICTED", "basis": "Growth not matched by capacity"}
        if any(f["check"] == "UNSUPPORTED_GROWTH" for f in findings) else
        {"level": "RECORD_MATCHED", "basis": f"Within intake approved in {changes['cycle']}"} if intake and intake["pct"] <= 0 else
        {"level": "EVIDENCE_ONLY", "basis": "Growth matched by added capacity"} if intake else
        {"level": "DECLARED_ONLY", "basis": "No previous approval on record"})})
    claims.append({"claim": "Classroom areas", "level": "DECLARED_ONLY", "basis": "Typed in the form; no measured floor plan"})
    claims.append({"claim": "Building age", "level": "DECLARED_ONLY", "basis": "Typed in the form"})
    for p in photos:
        claims.append({"claim": f"{p['label'].title()} photo", **(
            {"level": "CONTRADICTED", "basis": TITLE[against[p["file"]]]} if p["file"] in against else
            {"level": "EVIDENCE_ONLY", "basis": f"On campus ({p['distance_m']} m), looks like a {p['scene']}"})})
    return claims


def _ver(doc, source, status, response, compared):
    return {"doc": doc, "source": source, "status": status, "checked_at": datetime.now().isoformat(timespec="seconds"),
            "request_id": uuid.uuid4().hex[:10],
            "response_hash": hashlib.sha256(json.dumps(response, sort_keys=True, default=str).encode()).hexdigest()[:16],
            "compared_fields": compared}
