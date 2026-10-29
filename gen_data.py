"""Generate synthetic demo data: applications with planted defects, a test PKI, mock issuer registries.

Institutions, people and documents are fictional. Photos are real, licensed campus photos (assets/photos/CREDITS.md)
with synthetic GPS/date EXIF. Every file under data/apps is stored AES-256-GCM encrypted (storage.py).
Run: python gen_data.py
"""
import hashlib
import io
import json
import os
import random
import shutil
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pymupdf
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from PIL import Image, ImageEnhance, ImageFilter
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers
from pypdf import PdfReader, PdfWriter
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

import storage

BASE = Path(__file__).parent
DATA = storage.DATA
PHOTOS = BASE / "assets" / "photos"
APP_DATE = date(2026, 10, 20)
FIRST = ["Aditi", "Rahul", "Meera", "Arjun", "Kavya", "Vikram", "Sneha", "Rohan", "Ananya", "Karthik", "Pooja", "Imran",
         "Lakshmi", "Nikhil", "Farah", "Manoj"]
LAST = ["Sharma", "Reddy", "Iyer", "Patil", "Singh", "Nair", "Das", "Khan", "Joshi", "Menon", "Gupta", "Rao", "Bose", "Kulkarni"]

MASTER = {  # stands in for AICTE's institution records and approval history
    "1-111111": {"name": "Vidya Bharati College of Engineering", "signatory": "Anita Deshpande",
                 "lat": 18.5204, "lng": 73.8567, "state": "Maharashtra", "approved_intake": 180, "past_deficiencies": [],
                 "last_approval": {"cycle": "2025-26", "intake": 180, "faculty": 36, "classrooms": 3, "built_up_sqm": 18450}},
    "1-222222": {"name": "Sri Rama Institute of Engineering", "signatory": "Ramesh Kumar Sharma",
                 "lat": 17.3850, "lng": 78.4867, "state": "Telangana", "approved_intake": 240,
                 "past_deficiencies": ["FACULTY_RATIO"],
                 "last_approval": {"cycle": "2025-26", "intake": 240, "faculty": 48, "classrooms": 3, "built_up_sqm": 18450}},
    "1-333333": {"name": "Nalanda Institute of Technology", "signatory": "Priya Nair",
                 "lat": 12.9716, "lng": 77.5946, "state": "Karnataka", "approved_intake": 60, "past_deficiencies": [],
                 "last_approval": {"cycle": "2025-26", "intake": 60, "faculty": 18, "classrooms": 4, "built_up_sqm": 18450}},
    "1-444444": {"name": "Kaveri College of Engineering", "signatory": "Suresh Gowda",
                 "lat": 12.2958, "lng": 76.6394, "state": "Karnataka", "approved_intake": 120, "past_deficiencies": [],
                 "last_approval": {"cycle": "2025-26", "intake": 120, "faculty": 24, "classrooms": 2, "built_up_sqm": 18450}},
}


def d(x):
    return x.strftime("%d-%m-%Y")


def pdf_bytes(issuer, title, fields):
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    c.setFont("Helvetica-Bold", 15)
    c.drawCentredString(w / 2, h - 70, issuer)
    c.setFont("Helvetica-Bold", 13)
    c.drawCentredString(w / 2, h - 95, title)
    c.line(60, h - 108, w - 60, h - 108)
    c.setFont("Helvetica", 12)
    y = h - 145
    for k, v in fields:
        c.drawString(70, y, f"{k}: {v}")
        y -= 26
    c.setFont("Helvetica-Oblique", 8)
    c.drawString(60, 40, "SYNTHETIC DOCUMENT - generated for SIH 2026 prototype demo")
    c.save()
    return buf.getvalue()


def scanned(issuer, title, fields, tamper=None, seed=0):
    """Rasterise like a phone scan (noise, blur, JPEG). tamper=(label, new_value) pastes a clean re-typed patch
    over that line after the first JPEG save, the way an edited scan is made."""
    dpi = 140
    page = pymupdf.open(stream=pdf_bytes(issuer, title, fields))[0]
    img = Image.open(io.BytesIO(page.get_pixmap(dpi=dpi).tobytes("png"))).convert("RGB")
    rnd = np.random.default_rng(seed)
    arr = np.asarray(img).astype(np.float32) * np.array([0.97, 0.96, 0.92]) + rnd.normal(0, 7, (img.height, img.width, 1))
    img = Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8)).filter(ImageFilter.GaussianBlur(0.6))
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=72)
    img = Image.open(io.BytesIO(buf.getvalue())).convert("RGB")
    if tamper:
        label, new = tamper
        forged = [(k, new if k == label else v) for k, v in fields]
        fpage = pymupdf.open(stream=pdf_bytes(issuer, title, forged))[0]
        r = fpage.search_for(f"{label}: {new}")[0] * (dpi / 72)
        box = tuple(int(v) for v in (r.x0 - 6, r.y0 - 4, r.x1 + 10, r.y1 + 4))
        patch = Image.open(io.BytesIO(fpage.get_pixmap(dpi=dpi).tobytes("png"))).convert("RGB").crop(box)
        img.paste(patch, box[:2])
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=72)
    doc = pymupdf.open()
    doc.new_page(width=A4[0], height=A4[1]).insert_image(pymupdf.Rect(0, 0, *A4), stream=buf.getvalue())
    return doc.tobytes()


def make_pki(out):
    out.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.COUNTRY_NAME, "IN")])

    def ku(ca):
        return x509.KeyUsage(digital_signature=True, content_commitment=not ca, key_encipherment=False,
                             data_encipherment=False, key_agreement=False, key_cert_sign=ca, crl_sign=ca,
                             encipher_only=False, decipher_only=False)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = name("Pramaan Test Root CA (stand-in for CCA India 2022)")
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
          .not_valid_after(now + timedelta(days=3650))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(ku(True), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    (out / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    def leaf(cn, stem):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(ca_name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=730))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(ku(False), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                .sign(ca_key, hashes.SHA256()))
        (out / f"{stem}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (out / f"{stem}.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                            serialization.NoEncryption()))

    leaf("Authorised Signatory (Test DSC)", "signer")
    leaf("AICTE Approval Bureau (Test signing key)", "aicte")  # signs approval records; records.verify pins this exact certificate
    (out / "pan.salt").write_bytes(os.urandom(16))
    return signers.SimpleSigner.load(str(out / "signer.key"), str(out / "signer.pem"),
                                     ca_chain_files=(str(out / "ca.pem"),), key_passphrase=None)


def pan(n, i):
    """A synthetic, well-formed PAN (5 letters, 4 digits, 1 letter; 4th letter P = individual)."""
    r = random.Random(n * 1000 + i)
    L = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return "".join(r.choice(L) for _ in range(3)) + "P" + r.choice(L) + f"{r.randint(0, 9999):04d}" + r.choice(L)


def pan_hash(root, p):
    """Only a salted hash of each PAN is shared across institutions; the portal shows a masked PAN."""
    return hashlib.sha256((root / "pki" / "pan.salt").read_bytes() + p.encode()).hexdigest()


def roster(n, count, ghost_of=None, ghosts=0):
    """Faculty list for an application; the first `ghosts` people are copied from institution number ghost_of."""
    out = []
    for i in range(count):
        src_n, src_i = (ghost_of, i) if i < ghosts else (n, i)
        r = random.Random(src_n * 1000 + src_i)
        out.append({"name": f"Dr. {r.choice(FIRST)} {r.choice(LAST)}", "pan": pan(src_n, src_i)})
    return out


def register_faculty(registry, root, aicte_id, institution, people):
    for f in people:
        registry.setdefault("faculty", {}).setdefault(pan_hash(root, f["pan"]), []).append(
            {"aicte_id": aicte_id, "institution": institution, "name": f["name"], "cycle": "2026-27"})


def sign(data, signer):
    out = signers.sign_pdf(IncrementalPdfFileWriter(io.BytesIO(data)),
                           signers.PdfSignatureMetadata(field_name="AuthorisedSignatory"), signer=signer)
    return out.getvalue()


def edit_after_signing(data):
    """A post-signature edit: an incremental update that adds a line to page 1."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    c.setFont("Helvetica", 12)
    c.drawString(70, A4[1] - 145 - 26 * 6, "Approved Intake Declared: 300")
    c.save()
    w = PdfWriter(io.BytesIO(data), incremental=True)
    w.pages[0].merge_page(PdfReader(buf).pages[0])
    out = io.BytesIO()
    w.write(out)
    return out.getvalue()


def forge_record(data, field, new):
    """What a forger does to a signed PDF: white out one value and type a new one (an incremental update)."""
    r = pymupdf.open(stream=data)[0].search_for(f"{field}: ")[0]
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    c.setFillColorRGB(1, 1, 1)
    c.rect(r.x0 - 1, A4[1] - r.y1 - 2, 300, r.height + 4, stroke=0, fill=1)
    c.setFillColorRGB(0, 0, 0)
    c.setFont("Helvetica", 12)
    c.drawString(r.x0, A4[1] - r.y1 + 3, f"{field}: {new}")
    c.save()
    w = PdfWriter(io.BytesIO(data), incremental=True)
    w.pages[0].merge_page(PdfReader(buf).pages[0])
    out = io.BytesIO()
    w.write(out)
    return out.getvalue()


def dms(x):
    deg = int(x)
    m = int((x - deg) * 60)
    return (float(deg), float(m), round(((x - deg) * 60 - m) * 60, 2))


def photo(asset, gps, when, variant=0):
    im = Image.open(PHOTOS / asset).convert("RGB")
    if variant:  # a re-saved, resized copy: different bytes and size, same picture
        im = ImageEnhance.Brightness(im.resize((im.width * 9 // 10, im.height * 9 // 10))).enhance(1.05)
    ex = Image.Exif()
    if gps:
        ex[0x8825] = {1: "N", 2: dms(gps[0]), 3: "E", 4: dms(gps[1])}
    ex[0x0132] = when.strftime("%Y:%m:%d %H:%M:%S")
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=90, exif=ex)
    return buf.getvalue()


def documents(a, m, n):
    fire_valid = a["fire_valid"]
    oc_no = f"OC/{n}/2014/0771"
    return {
        "affidavit.pdf": ("Notary Public / Oath Commissioner", "AFFIDAVIT 2 (Rs.100 e-Stamp)", [
            ("Institution Name", m["name"]), ("AICTE Permanent ID", a["aicte_id"]),
            ("Signatory", a.get("signatory") or m["signatory"]), ("E-Stamp No", f"IN-DL{n}48213907"),
            ("E-Stamp Date", d(APP_DATE - timedelta(days=9))), ("Affidavit Date", d(APP_DATE - timedelta(days=7)))]),
        "fee_receipt.pdf": ("AICTE Web Portal", "PAYMENT RECEIPT", [
            ("Transaction ID", f"AICTE2026TX{n}0912"), ("AICTE Permanent ID", a["aicte_id"]),
            ("Amount", "Rs. 1,00,000"), ("Payment Date", d(APP_DATE - timedelta(days=12)))]),
        "occupancy_certificate.pdf": (f"Municipal Corporation, {m['state']}", "OCCUPANCY CERTIFICATE", [
            ("Certificate No", oc_no), ("Institution Name", m["name"]), ("Issue Date", d(date(2014, 3, 11))),
            ("Built-up Area (sq m)", "18450"), ("DigiLocker URI", f"in.gov.{m['state'][:2].lower()}.ulb-OCCER-{n}0771"),
            ("Land Survey No", a.get("survey") or f"SY-{m['state'][:3].upper()}-{n:04d}"), ("Land Area (acres)", a.get("acres", "12.40"))]),
        "fire_noc.pdf": (f"State Fire & Emergency Services, {m['state']}", "FIRE SAFETY CERTIFICATE / NOC", [
            ("NOC No", f"FIRE/{m['state'][:3].upper()}/2025/{n}390"), ("Institution Name", a.get("fire_name") or m["name"]),
            ("Issue Date", d(fire_valid - timedelta(days=365))), ("Valid Upto", d(fire_valid))]),
        "satellite_map.pdf": ("Institution (self-declared)", "SATELLITE MAP - MAIN BUILDING ENTRANCE", [
            ("Latitude", f"{m['lat']:.4f}"), ("Longitude", f"{m['lng']:.4f}")]),
        "audited_accounts.pdf": ("Chartered Accountant", "AUDITED ACCOUNTS", [
            ("Institution Name", m["name"]), ("Financial Year", "2025-26"), ("UDIN", f"26{n}12345ABCDE6789")]),
        "university_noc.pdf": ("Affiliating University", "NO OBJECTION CERTIFICATE (Format 2)", [
            ("Institution Name", m["name"]), ("Proposed Intake", str(a["proposed_intake"])),
            ("Issue Date", d(APP_DATE - timedelta(days=30)))]),
    }


def build_app(a, master, signer, registry, root):
    """Write one application. Also used by bench.py with randomised specs."""
    m = master[a["aicte_id"]]
    folder = root / "apps" / a["id"]
    n = a["n"]
    docs = documents(a, m, n)
    for fname, (issuer, title, fields) in docs.items():
        if fname in a.get("missing", []) or (fname == "university_noc.pdf" and a["category"] != "INCREASE_INTAKE"):
            continue
        if fname == "fire_noc.pdf" and a.get("fire_copy_of") in FILES:  # the same file another college submitted
            data = FILES[a["fire_copy_of"]]
        elif fname == "fire_noc.pdf" and a.get("scan_fire"):
            data = scanned(issuer, title, fields, a.get("tamper_fire"), seed=n)
        else:
            data = pdf_bytes(issuer, title, fields)
        if fname == "affidavit.pdf":
            data = sign(data, signer)
            if a.get("tamper_affidavit"):
                data = edit_after_signing(data)
        if fname == "occupancy_certificate.pdf" and a.get("oc_registered", True):
            registry["digilocker"][dict(fields)["DigiLocker URI"]] = {
                "doc_type": "OCCUPANCY_CERTIFICATE", "issuer": issuer, "sha256": hashlib.sha256(data).hexdigest()}
        storage.write(folder / fname, data)
    f = dict(docs["fire_noc.pdf"][2])
    registry["fire"][f["NOC No"]] = {"institution": m["name"], "valid_upto": d(a["fire_valid"])}
    registry["payments"][dict(docs["fee_receipt.pdf"][2])["Transaction ID"]] = {"aicte_id": a["aicte_id"]}

    people = roster(n, a["faculty"], a.get("ghost_of"), a.get("ghosts", 0))
    register_faculty(registry, root, a["aicte_id"], m["name"], people)

    shot = datetime(2026, 9, 15, 11, 0)
    for p in a["photos"]:
        gps = None if p["offset"] is None else (m["lat"] + p["offset"], m["lng"])
        storage.write(folder / "photos" / p["file"], photo(p["asset"], gps, shot, p.get("variant", 0)))
    (folder / "application.json").write_text(json.dumps({
        "id": a["id"], "aicte_id": a["aicte_id"], "institution": m["name"], "category": a["category"],
        "status": a.get("status", "SUBMITTED"), "programme_level": "UG Engineering",
        "application_date": APP_DATE.isoformat(), "submitted_at": a["submitted_at"],
        "proposed_intake": a["proposed_intake"], "faculty_count": a["faculty"], "classroom_areas_sqm": a["classrooms"],
        "building_age_years": a["building_age"],
        "faculty_roster": [{"name": f["name"], "pan_masked": f["pan"][:5] + "****" + f["pan"][-1],
                            "pan_hash": pan_hash(root, f["pan"])} for f in people],
        "photos": [{"file": f"photos/{p['file']}", "label": p["label"]} for p in a["photos"]],
    }, indent=2))


def inbox(registry, root):
    """Plain files on the 'institution's computer', uploaded during the demo."""
    m, a = MASTER["1-444444"], {"aicte_id": "1-444444", "proposed_intake": 120, "fire_valid": date(2027, 9, 30)}
    docs = documents(a, m, 4)
    issuer, title, fields = docs["fire_noc.pdf"]
    fields = [(k, "FIRE/KAR/2026/4391" if k == "NOC No" else v) for k, v in fields]  # a renewal gets a new number
    docs["fire_noc.pdf"] = (issuer, title, fields)
    (root / "inbox").mkdir(parents=True, exist_ok=True)
    (root / "inbox" / "fire_noc_renewed.pdf").write_bytes(pdf_bytes(*docs["fire_noc.pdf"]))
    (root / "inbox" / "audited_accounts.pdf").write_bytes(pdf_bytes(*docs["audited_accounts.pdf"]))
    registry["fire"][dict(docs["fire_noc.pdf"][2])["NOC No"]] = {"institution": m["name"], "valid_upto": d(a["fire_valid"])}
    # Nalanda's correction round: the missing accounts it was asked for, plus a university NOC it was not asked to change
    n_spec, n_master = next(a for a in DEMO if a["id"] == "APP-3"), MASTER["1-333333"]
    n_docs = documents(n_spec, n_master, 3)
    (root / "inbox" / "nalanda_audited_accounts.pdf").write_bytes(pdf_bytes(*n_docs["audited_accounts.pdf"]))
    issuer, title, fields = n_docs["university_noc.pdf"]
    (root / "inbox" / "nalanda_university_noc.pdf").write_bytes(
        pdf_bytes(issuer, title, [(k, "240" if k == "Proposed Intake" else v) for k, v in fields]))
    # a norms circular the approver imports on the Rules page: UG classroom norm lowered from 66 to 50 m²
    norms = [("Circular No", "AICTE/P&AP/Norms/2026-27/04"), ("Effective From", "01-11-2026")]
    for programme, room in (("UG Engineering", 50), ("Diploma", 66), ("Any other programme", 66)):
        norms += [("Programme level", programme), ("Minimum classroom area (m²)", room),
                  ("Maximum students per faculty member", 25 if programme == "Diploma" else 20),
                  ("Minimum computers visible in a lab photo", 3)]
    (root / "inbox" / "norms_circular_2026-27.pdf").write_bytes(pdf_bytes("AICTE Policy and Academic Planning Bureau",
                                                                          "NORMS CIRCULAR 2026-27", norms))


DEMO = [
    # APP-1: clean reference application
    dict(id="APP-1", n=1, aicte_id="1-111111", category="EOA_SELF_DISCLOSURE", proposed_intake=180, faculty=36,
         classrooms=[66, 70, 66], building_age=12, fire_valid=date(2027, 6, 30), submitted_at="2026-10-16T10:00:00",
         photos=[dict(label="lab", file="lab1.jpg", asset="lab_c.jpg", offset=0),
                 dict(label="classroom", file="classroom1.jpg", asset="classroom_a.jpg", offset=0)]),
    # APP-2: the main demo case
    dict(id="APP-2", n=2, aicte_id="1-222222", category="EOA_SELF_DISCLOSURE", proposed_intake=240, faculty=36,
         classrooms=[66, 52, 66], building_age=18, fire_valid=date(2026, 10, 8), submitted_at="2026-10-18T10:00:00",
         fire_name="Sree Ramana Inst. of Engg & Tech", signatory="R. K. Sarma", tamper_affidavit=True,
         scan_fire=True, tamper_fire=("Valid Upto", "08-10-2027"), ghost_of=5, ghosts=4,
         photos=[dict(label="lab", file="lab1.jpg", asset="lab_c.jpg", offset=0, variant=1),
                 dict(label="classroom", file="classroom1.jpg", asset="classroom_b.jpg", offset=0)]),
    # APP-3: increase-in-intake, second checklist from the same rules
    dict(id="APP-3", n=3, aicte_id="1-333333", category="INCREASE_INTAKE", proposed_intake=180, faculty=30,
         classrooms=[66, 66, 66, 66], building_age=9, fire_valid=date(2027, 1, 5), submitted_at="2026-10-20T10:00:00",
         missing=["audited_accounts.pdf"], oc_registered=False,
         photos=[dict(label="classroom", file="classroom1.jpg", asset="classroom_c.jpg", offset=0.029),
                 dict(label="lab", file="lab1.jpg", asset="library_a.jpg", offset=None)]),
    # APP-4: draft the institution fixes during the demo (expired NOC, missing accounts)
    dict(id="APP-4", n=4, aicte_id="1-444444", category="EOA_SELF_DISCLOSURE", proposed_intake=120, faculty=24,
         classrooms=[66, 66], building_age=6, fire_valid=date(2026, 8, 31), submitted_at="2026-10-22T10:00:00",
         status="DRAFT", missing=["audited_accounts.pdf"],
         photos=[dict(label="lab", file="lab1.jpg", asset="lab_b.jpg", offset=0)]),
]


# Demo sign-ins (synthetic test accounts; only PBKDF2 hashes are written to data/users.json).
DEMO_USERS = {
    "officer.k": ("scrutiny_officer", "K. Iyer, Scrutiny Officer", "scrutiny@2026"),
    "officer.m": ("scrutiny_officer", "M. Das, Scrutiny Officer", "scrutiny@2026"),
    "approver.r": ("approver", "R. Menon, Regional Officer", "approver@2026"),
    "auditor.v": ("auditor", "V. Joshi, Internal Audit", "auditor@2026"),
    "pramaan-ai": ("ai-service", "Pramaan AI service account", "service@2026"),
    **{aid: ("institution", m["name"], "college@2026") for aid, m in MASTER.items()},
}


def write_users(root):
    import auth
    out = {}
    for name, (role, display, password) in DEMO_USERS.items():
        salt, h = auth.hash_password(password)
        out[name] = {"role": role, "name": display, "salt": salt, "hash": h}
    (root / "users.json").write_text(json.dumps(out, indent=2))


FILES = {}  # n -> fire NOC bytes, so a later national application can reuse an earlier one's file
STATES = {"Maharashtra": (18.52, 73.86), "Telangana": (17.39, 78.49), "Karnataka": (12.97, 77.59), "Tamil Nadu": (13.08, 80.27),
          "Uttar Pradesh": (26.85, 80.95), "Rajasthan": (26.91, 75.79), "Gujarat": (23.02, 72.57), "Kerala": (10.85, 76.27)}
PLACES = ["Godavari", "Narmada", "Sahyadri", "Aravalli", "Tapti", "Mahanadi", "Satpura", "Vindhya", "Krishna", "Tungabhadra",
          "Pennar", "Kaveri Valley", "Nilgiri", "Konkan", "Malwa", "Deccan"]
KINDS = ["Institute of Technology", "College of Engineering", "Institute of Engineering", "Engineering College"]


def national(registry, signer, root, count=48):
    """More synthetic colleges so the queue, the inspection planner and the network look like a regional office's year.
    Planted patterns: ghost-faculty rings, a shared fire-NOC file, land shown by two colleges, expired NOCs, shortfalls."""
    rnd = random.Random(2026)
    specs = []
    for i in range(count):
        n = 100 + i
        aid = f"1-{700000 + i:06d}"
        state = rnd.choice(sorted(STATES))
        lat, lng = STATES[state]
        name = f"{PLACES[i % len(PLACES)]} {KINDS[(i // len(PLACES) + i) % len(KINDS)]}, {state}"
        intake = rnd.choice([60, 120, 180])
        MASTER[aid] = {"name": name, "signatory": f"{rnd.choice(FIRST)} {rnd.choice(LAST)}",
                       "lat": round(lat + rnd.uniform(-0.3, 0.3), 4), "lng": round(lng + rnd.uniform(-0.3, 0.3), 4),
                       "state": state, "approved_intake": intake, "past_deficiencies": [],
                       "last_approval": {"cycle": "2025-26", "intake": intake, "faculty": intake * 4 // 18, "classrooms": 3,
                                         "built_up_sqm": 18450}}
        a = dict(id=f"APP-{5 + i}", n=n, aicte_id=aid, category="EOA_SELF_DISCLOSURE", proposed_intake=intake,
                 faculty=intake * 4 // 18, classrooms=[66, 70, 66], building_age=rnd.randint(4, 25),
                 fire_valid=date(2027, rnd.randint(1, 12), 15), submitted_at=f"2026-10-{1 + i % 15:02d}T{9 + i % 8}:00:00", photos=[])
        roll = rnd.random()
        if i in (3, 4, 5):  # a ring: three colleges list the same 3 teachers
            a.update(ghost_of=900, ghosts=3)
        elif i in (11, 12):
            a.update(ghost_of=901, ghosts=5)
        elif i == 20:
            a.update(fire_copy_of=119)  # the fire NOC file of college 19, byte for byte
        elif i in (27, 28):
            a.update(survey="SY-TEL-0771", acres="10.29")  # the JNTU-H pattern: the same land shown twice
        elif roll < 0.12:
            a.update(fire_valid=date(2026, 8, 31))
        elif roll < 0.22:
            a.update(classrooms=[66, 48, 66])
        elif roll < 0.3:
            a.update(faculty=intake * 4 // 28)
        elif roll < 0.36:
            a.update(proposed_intake=intake * 2)
        elif roll < 0.42:
            a.update(missing=["audited_accounts.pdf"])
        specs.append(a)
    for a in specs:  # ghost faculty must be registered for every college before any is checked; files need their source first
        build_app(a, MASTER, signer, registry, root)
        FILES[a["n"]] = storage.read(root / "apps" / a["id"] / "fire_noc.pdf")
    return len(specs)


def build():
    if DATA.exists():
        shutil.rmtree(DATA)
    signer = make_pki(DATA / "pki")
    registry = {"fire": {}, "ulb": {}, "payments": {}, "digilocker": {}, "faculty": {}}
    # an institution outside the demo queue, as the AICTE faculty portal would hold it
    register_faculty(registry, DATA, "1-555555", "Ganga Institute of Technology, Patna", roster(5, 40))
    for a in DEMO:
        build_app(a, MASTER, signer, registry, DATA)
    extra = national(registry, signer, DATA)
    inbox(registry, DATA)
    (DATA / "master.json").write_text(json.dumps(MASTER, indent=2))
    (DATA / "registry.json").write_text(json.dumps(registry, indent=2))
    write_users(DATA)
    print("Generated", len(DEMO) + extra, "applications in", DATA)


if __name__ == "__main__":
    random.seed(7)
    build()
