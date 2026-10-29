"""Signed approval records: after an approver approves, AICTE issues a PDF signed with its own key and a QR code.

Anyone (a student, a parent, a bank) can scan the QR or upload their copy to /check.html: the signature shows whether
the copy is exactly what AICTE issued, and the register shows how much of the approval was independently verified.
shortcut: the AICTE key is a test key under the Pramaan test root; production uses an HSM-held key under CCA India.
"""
import hashlib
import io
import secrets
from datetime import datetime

import pymupdf
from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers
from reportlab.graphics import renderPDF
from reportlab.graphics.barcode.qr import QrCodeWidget
from reportlab.graphics.shapes import Drawing
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

import checks
import storage

DATA = storage.DATA
CYCLE = "2026-27"
SHORT = {"ISSUER_CONFIRMED": "Issuer-confirmed", "RECORD_MATCHED": "AICTE record", "SIGNED_INTACT": "Signed, intact",
         "EVIDENCE_ONLY": "Evidence only", "DECLARED_ONLY": "Declared only", "CONTRADICTED": "Contradicted"}


def _pdf(rec, url):
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    c.setFont("Helvetica-Bold", 15)
    c.drawCentredString(w / 2, h - 70, "All India Council for Technical Education")
    c.setFont("Helvetica-Bold", 13)
    c.drawCentredString(w / 2, h - 95, f"VERIFIED APPROVAL RECORD - EXTENSION OF APPROVAL {CYCLE}")
    c.line(60, h - 108, w - 60, h - 108)
    c.setFont("Helvetica", 12)
    y = h - 145
    for k, v in (("Record ID", rec["id"]), ("Institution Name", rec["institution"]), ("AICTE Permanent ID", rec["aicte_id"]),
                 ("Category", rec["category"]), ("Approved Intake", rec["intake"]), ("Decision", "Approved"),
                 ("Decided By", rec["decided_by"]), ("Decision Date", rec["decided_at"][:10]), ("Rules Version", rec["rules_version"]),
                 ("Proof Score", f"{rec['proof_score']}/100 ({rec['independent_pct']}% independently confirmed)")):
        c.drawString(70, y, f"{k}: {v}")
        y -= 24
    y -= 8
    c.setFont("Helvetica-Bold", 11)
    c.drawString(70, y, "How each claim was proven")
    c.setFont("Helvetica", 10)
    for cl in rec["claims"]:
        y -= 17
        c.drawString(80, y, f"- {cl['claim']}")
        c.drawString(260, y, SHORT[cl["level"]])
        c.drawString(360, y, cl["basis"].split(" (demo")[0][:42])
    qr = QrCodeWidget(url)
    x0, y0, x1, y1 = qr.getBounds()
    d = Drawing(110, 110, transform=[110 / (x1 - x0), 0, 0, 110 / (y1 - y0), 0, 0])
    d.add(qr)
    renderPDF.draw(d, c, w - 175, 60)
    c.setFont("Helvetica", 9)
    c.drawString(60, 110, "Digitally signed by AICTE. Any change to this file breaks the signature.")
    c.drawString(60, 96, "Scan the QR code, or upload this file at:")
    c.drawString(60, 82, url.split("?")[0])
    c.setFont("Helvetica-Oblique", 8)
    c.drawString(60, 40, "SYNTHETIC DOCUMENT - generated for SIH 2026 prototype demo")
    c.save()
    return buf.getvalue()


def issue(app, run, decision, base_url):
    """Create, sign and store the record. Returns the register entry."""
    rid = f"REC-{CYCLE[:4]}-{secrets.token_hex(3).upper()}"
    rec = {"id": rid, "app": app["id"], "institution": app["institution"], "aicte_id": app["aicte_id"],
           "category": run["category_label"], "intake": app["proposed_intake"], "cycle": CYCLE,
           "decided_by": f"{decision['maker']} (approver)", "decided_at": decision["at"], "rules_version": run["rules_version"],
           "proof_score": run["proof"]["score"], "independent_pct": run["proof"]["independent_pct"],
           "proof_counts": run["proof"]["counts"], "claims": run["proof"]["claims"],
           "evidence_digest": hashlib.sha256("".join(run["doc_hashes"].values()).encode()).hexdigest()}
    url = f"{base_url}check.html?id={rid}"
    pdf = sign(_pdf(rec, url))
    storage.write(DATA / "records" / f"{rid}.pdf", pdf)
    rec.update(sha256=hashlib.sha256(pdf).hexdigest(), issued_at=datetime.now().isoformat(timespec="seconds"), url=url)
    return rec


def sign(data):
    """Sign a PDF with AICTE's key (test key in the prototype)."""
    signer = signers.SimpleSigner.load(str(DATA / "pki" / "aicte.key"), str(DATA / "pki" / "aicte.pem"),
                                       ca_chain_files=(str(DATA / "pki" / "ca.pem"),), key_passphrase=None)
    return signers.sign_pdf(IncrementalPdfFileWriter(io.BytesIO(data)),
                            signers.PdfSignatureMetadata(field_name="AICTE"), signer=signer).getvalue()


def deficiency_letter(app, rect):
    """A signed deficiency letter that lists exactly what the college must fix, so the re-check can hold it to that list."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    c.setFont("Helvetica-Bold", 15)
    c.drawCentredString(w / 2, h - 70, "All India Council for Technical Education")
    c.setFont("Helvetica-Bold", 13)
    c.drawCentredString(w / 2, h - 95, f"DEFICIENCY LETTER - CORRECTION ROUND {rect['round']}")
    c.line(60, h - 108, w - 60, h - 108)
    c.setFont("Helvetica", 11)
    y = h - 140
    for line in (f"To: {app['institution']} (AICTE {app['aicte_id']})", f"Application: {app['id']}",
                 f"Issued: {rect['requested_at'][:10]}    Reply by: {rect['due']}",
                 f"Decided by: {rect['maker']}, confirmed by {rect['checker']}", "",
                 "Please correct only the items below and resubmit. Changes to anything else will be flagged."):
        c.drawString(70, y, line)
        y -= 18
    y -= 6
    for i, it in enumerate(rect["items"], 1):
        c.setFont("Helvetica-Bold", 11)
        c.drawString(70, y, f"{i}. {it['title']}" + (f"  ({it['doc']})" if it["doc"] else ""))
        y -= 16
        c.setFont("Helvetica", 10)
        text = it["message"]
        while text:
            c.drawString(86, y, text[:95])
            text, y = text[95:], y - 14
        y -= 6
    c.setFont("Helvetica-Oblique", 8)
    c.drawString(60, 40, "SYNTHETIC DOCUMENT - generated for SIH 2026 prototype demo")
    c.save()
    return sign(buf.getvalue())


ON_SITE = {  # what an expert team checks in person for each kind of finding
    "AREA_SHORTFALL": "Measure the classrooms named in the finding with a tape; photograph each with the tape visible.",
    "FACULTY_RATIO": "Count faculty present against the declared list; collect attendance and salary registers.",
    "GHOST_FACULTY": "Meet the named faculty; check appointment letters, attendance and bank salary credits for this college.",
    "EQUIPMENT_LOW": "Count working computers in each lab; note make and serial numbers of a sample.",
    "SCENE_MISMATCH": "Visit the room declared as a lab; photograph it with GPS on.",
    "DUPLICATE_PHOTO": "Photograph the actual lab and classrooms with GPS and time on; compare with the submitted photos.",
    "GPS_FAR": "Take geotagged photos at the main entrance and of each declared facility.",
    "GPS_MISSING": "Take geotagged photos at the main entrance and of each declared facility.",
    "SCAN_TAMPER": "See the original fire NOC; inspect extinguishers, alarms and exits; call the issuing fire office.",
    "SOURCE_MISMATCH": "See the original certificate and confirm it with the issuing office during the visit.",
    "DOC_EXPIRED": "See the current certificate, or confirm the renewal application with the issuing office.",
    "VALUE_COVERED": "See the original paper certificate; compare the covered value with what is printed.",
    "IDENTICAL_FILE": "See the original certificate; confirm its number and address belong to this campus.",
    "LAND_REUSED": "Verify the survey number on the ground and see the original title deed and land records.",
    "EDITED_AFTER_SIGNING": "Meet the authorised signatory; see the original signed affidavit.",
    "SIGNATORY_MISMATCH": "Meet the authorised signatory; check the board resolution that names them.",
    "UNSUPPORTED_GROWTH": "Count the classrooms, labs and faculty that support the added seats.",
    "STRUCTURAL_REQUIRED": "See the structural stability certificate and inspect visible cracks or damage.",
    "NAME_MISMATCH": "Check the name on the trust deed and registration against the documents.",
}


def inspection_brief(app, master, run, inspect_with):
    """A two-page brief for an expert team: why this visit, what to check on site, and who else to cover on the trip."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4

    def line(text, y, size=10, bold=False, indent=70):
        c.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        while text:
            c.drawString(indent, y, text[:100])
            text, y = text[100:], y - (size + 4)
        return y

    c.setFont("Helvetica-Bold", 15)
    c.drawCentredString(w / 2, h - 70, "All India Council for Technical Education")
    c.setFont("Helvetica-Bold", 13)
    c.drawCentredString(w / 2, h - 95, "INSPECTION BRIEF - EXPERT VISIT COMMITTEE")
    c.line(60, h - 108, w - 60, h - 108)
    y = h - 135
    for t in (f"College: {app['institution']} (AICTE {app['aicte_id']}, {app['id']})",
              f"State: {master['state']}   Campus entrance: {master['lat']}, {master['lng']}",
              f"Proof score {run['proof']['score']}/100, {run['proof']['independent_pct']}% independently confirmed, "
              f"{run['proof']['counts']['CONTRADICTED']} claims contradicted. Rules {run['rules_version']}.",
              "Findings are preliminary indicators for the team to verify, not conclusions."):
        y = line(t, y) - 4
    y = line("Why this visit, and what to check on site", y - 8, 12, True)
    high = [f for f in run["findings"] if f["severity"] == "HIGH"]
    for f in high:
        if y < 120:
            c.showPage()
            y = h - 70
        y = line(f"[F{f['id']}] {f['title']} ({f['clause']})", y - 6, 10, True)
        y = line(f["message"], y, 9, indent=82)
        y = line("On site: " + ON_SITE.get(f["check"], "Verify the underlying document against the original."), y, 9, indent=82)
    declared = [cl["claim"] for cl in run["proof"]["claims"] if cl["level"] == "DECLARED_ONLY"]
    if declared:
        y = line("Only declared, never evidenced - verify in person", y - 10, 12, True)
        y = line(", ".join(declared), y - 2, 10)
    if inspect_with:
        y = line("Cover on the same trip (shared faculty, photos, files or land)", y - 10, 12, True)
        y = line(", ".join(inspect_with), y - 2, 10)
    c.setFont("Helvetica-Oblique", 8)
    c.drawString(60, 40, "SYNTHETIC DOCUMENT - generated for SIH 2026 prototype demo")
    c.save()
    return buf.getvalue()


def pdf(rid):
    return storage.read(DATA / "records" / f"{rid}.pdf")


def preview(data):
    return pymupdf.open(stream=data)[0].get_pixmap(dpi=110).tobytes("png")


def verify(data, register):
    """Check an uploaded copy: AICTE's signature, edits after signing, and the register."""
    sha = hashlib.sha256(data).hexdigest()
    claimed = checks.extract(data, "record", [])["fields"]  # what this copy says, later lines win
    original = register.get(claimed.get("Record ID", ""))
    sig = checks.validate_dsc(data)
    if sig is None:
        status, why = "UNSIGNED", "This file carries no digital signature, so nothing proves AICTE issued it."
    elif not (sig["intact"] and sig["valid"]):
        status, why = "BROKEN_SIGNATURE", "The signature does not match the file's contents."
    elif sig["coverage"] != "ENTIRE_FILE" or not sig["docmdp_ok"]:
        status, why = "EDITED_AFTER_SIGNING", (f"This copy was changed after AICTE signed it ({sig['revisions']} revisions). "
                                                "Trust the register, not this copy.")
    elif not sig["trusted"] or sig["cert_sha256"] != hashlib.sha256(
            load_cert_from_pemder(str(DATA / "pki" / "aicte.pem")).dump()).hexdigest():
        status, why = "NOT_AICTE", f"Signed, but by '{sig['signer']}', not by AICTE."
    elif not any(r["sha256"] == sha for r in register.values()):
        status, why = "NOT_IN_REGISTER", "Signed by AICTE, but this record is not in the public register (withdrawn or replaced)."
    else:
        status, why = "GENUINE", "Exactly the file AICTE issued: the signature is valid and the copy matches the register."
    diffs = [{"field": k, "copy": claimed[k], "register": str(original[f])}
             for k, f in (("Institution Name", "institution"), ("Approved Intake", "intake"), ("AICTE Permanent ID", "aicte_id"))
             if original and k in claimed and claimed[k] != str(original[f])]
    return {"status": status, "explanation": why, "signer": sig and sig["signer"],
            "record": original, "differences": diffs}
