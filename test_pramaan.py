"""Self-check: regenerates the demo data, then asserts each planted defect is caught and every guard holds.
Run: python test_pramaan.py   (first run downloads nothing; CV results are cached in .cv_cache.json)"""
import json

from fastapi.testclient import TestClient

import gen_data
import storage

gen_data.build()
import app as pramaan  # noqa: E402  (data must exist before the app mounts)


def as_(user):
    """A browser signed in as one demo user."""
    c = TestClient(pramaan.app)
    assert c.post("/api/login", json={"username": user, "password": gen_data.DEMO_USERS[user][2]}).status_code == 200
    return c


anon = TestClient(pramaan.app)
OFF, APR, INST, AI, AUD = as_("officer.k"), as_("approver.r"), as_("1-444444"), as_("pramaan-ai"), as_("auditor.v")
checks_of = lambda a, c=OFF: {f["check"] for f in c.post(f"/api/apps/{a}/run").json()["findings"]}
norms_backup = pramaan.checks.NORMS_FILE.read_text(encoding="utf-8")
rules_backup = pramaan.checks.RULES_FILE.read_text(encoding="utf-8")

# sign-in: no session, wrong password, forged headers and forged cookies all get nothing
assert anon.get("/api/apps").status_code == 401
assert anon.post("/api/login", json={"username": "officer.k", "password": "wrong"}).status_code == 401
brute = TestClient(pramaan.app)
assert [brute.post("/api/login", json={"username": "x", "password": "y"}).status_code for _ in range(6)][-1] == 429
pramaan.FAILED.clear()
assert anon.get("/api/apps", headers={"X-Role": "approver", "X-User": "approver.r"}).status_code == 401
assert TestClient(pramaan.app, cookies={"pramaan_session": "eyJ1IjoiYXBwcm92ZXIuciJ9.deadbeef"}).get("/api/apps").status_code == 401
assert OFF.get("/api/me").json()["role"] == "scrutiny_officer"
assert OFF.get("/api/apps/APP-2", headers={"X-Role": "institution", "X-User": "1-222222"}).json()["application"]  # header ignored

# every file at rest is encrypted
assert all(p.read_bytes().startswith(storage.MAGIC) for p in (gen_data.DATA / "apps").rglob("*") if p.suffix in (".pdf", ".jpg"))

assert checks_of("APP-1") == set(), "clean application must have no findings"
assert checks_of("APP-2") == {"NAME_MISMATCH", "SIGNATORY_MISMATCH", "EDITED_AFTER_SIGNING", "SCAN_TAMPER", "DUPLICATE_PHOTO",
                              "AREA_SHORTFALL", "FACULTY_RATIO", "REPEAT_DEFICIENCY", "SOURCE_MISMATCH", "GHOST_FACULTY"}
assert checks_of("APP-3") == {"DOC_MISSING", "DOC_EXPIRING", "GPS_FAR", "GPS_MISSING", "SCENE_MISMATCH", "EQUIPMENT_LOW",
                              "FACULTY_RATIO", "SOURCE_MISMATCH", "UNSUPPORTED_GROWTH"}

r = OFF.get("/api/apps/APP-2").json()["run"]
assert r["outcome"] == "RECOMMEND_INSPECTION"
assert {v["doc"]: v["status"] for v in r["verifications"]}["fire_noc.pdf"] == "EXPIRED"
assert r["extraction"]["fire_noc.pdf"]["method"].startswith("Read from the scanned image")
assert r["extraction"]["fire_noc.pdf"]["fields"]["Valid Upto"] == "08-10-2027"  # OCR reads the forged date
assert "4 of 36" in next(f["message"] for f in r["findings"] if f["check"] == "GHOST_FACULTY")
assert {v["doc"]: v["status"] for v in OFF.get("/api/apps/APP-3").json()["run"]["verifications"]}[
    "occupancy_certificate.pdf"] == "MISMATCH"  # DigiLocker has no such issued document

# proof levels: the clean app is mostly proven, the forged one is mostly contradicted
p1 = OFF.get("/api/apps/APP-1").json()["run"]["proof"]
assert p1["counts"]["CONTRADICTED"] == 0 and p1["counts"]["ISSUER_CONFIRMED"] == 2 and p1["score"] > r["proof"]["score"]
assert {c["claim"]: c["level"] for c in r["proof"]["claims"]}["Faculty strength (36)"] == "CONTRADICTED"
p3 = OFF.get("/api/apps/APP-3").json()["run"]
assert {c["claim"]: c["level"] for c in p3["proof"]["claims"]}["Intake (180)"] == "CONTRADICTED"
assert p3["changes"]["rows"][0] == {"field": "intake", "then": 60, "now": 180, "pct": 200}

# evidence renders for every kind, and only for signed-in people allowed to see it
for f in r["findings"]:
    for e in f["evidence"]:
        resp = OFF.get("/api/evidence", params={"app": e["app"], "doc": e["doc"], "kind": e["kind"], "finding": f["id"]})
        assert resp.status_code == 200 and len(resp.content) > 1000, (f["check"], e)
assert anon.get("/api/evidence", params={"app": "APP-2", "doc": "affidavit.pdf"}).status_code == 401
assert INST.get("/api/evidence", params={"app": "APP-2", "doc": "affidavit.pdf"}).status_code == 403

# source outage -> SOURCE_UNAVAILABLE, not a crash
assert INST.post("/api/sources", json={"down": ["fire"]}).status_code == 403
OFF.post("/api/sources", json={"down": ["fire"]})
v = {x["doc"]: x["status"] for x in OFF.post("/api/apps/APP-1/run").json()["verifications"]}
assert v["fire_noc.pdf"] == "SOURCE_UNAVAILABLE"
OFF.post("/api/sources", json={"down": []})
OFF.post("/api/apps/APP-1/run")

# institution flow: drafts are invisible to officers, fixes clear the pre-check, then submit
assert "APP-4" not in {a["id"] for a in OFF.get("/api/apps").json()}
assert OFF.post("/api/apps/APP-4/run").status_code == 403
assert checks_of("APP-4", INST) == {"DOC_MISSING", "DOC_EXPIRED"}
assert INST.post("/api/apps/APP-4/submit").status_code == 409
assert as_("1-111111").post("/api/apps/APP-4/documents", data={"doc_type": "fire_noc.pdf"},
                            files={"file": ("x.pdf", b"%PDF-1.4")}).status_code == 403
assert INST.post("/api/apps/APP-4/documents", data={"doc_type": "../x.pdf"}, files={"file": ("x.pdf", b"%PDF-1.4")}).status_code == 422
assert INST.post("/api/apps/APP-4/documents", data={"doc_type": "fire_noc.pdf"}, files={"file": ("x.exe", b"MZ...")}).status_code == 422
for doc, name in (("fire_noc.pdf", "fire_noc_renewed.pdf"), ("audited_accounts.pdf", "audited_accounts.pdf")):
    body = (gen_data.DATA / "inbox" / name).read_bytes()
    assert INST.post("/api/apps/APP-4/documents", data={"doc_type": doc},
                     files={"file": (name, body, "application/pdf")}).status_code == 200
assert checks_of("APP-4", INST) == set()
assert INST.post("/api/apps/APP-4/submit").json()["status"] == "SUBMITTED"
assert "APP-4" in {a["id"] for a in OFF.get("/api/apps").json()}

# webhook intake needs the portal token
wh = {"aicte_id": "1-111111", "category": "INCREASE_INTAKE", "proposed_intake": 240, "faculty_count": 48,
      "classroom_areas_sqm": [66], "building_age_years": 3}
assert anon.post("/api/webhook/application", json=wh).status_code == 401
assert anon.post("/api/webhook/application", json=wh, headers={"X-Portal-Token": "demo-portal-token"}).json()["status"] == "DRAFT"

# inspection plan: the forged application comes first, and linked colleges go into the same visit
plan = OFF.get("/api/inspection-plan", params={"budget": 3}).json()
assert plan["plan"][0]["app"] == "APP-2" and plan["visits"] <= 3
assert {"Ganga Institute of Technology, Patna", "Vidya Bharati College of Engineering"} <= set(plan["plan"][0]["inspect_with"])
assert INST.get("/api/inspection-plan").status_code == 403

# Ask Pramaan: grounded in what the role may see; a college cannot ask about another college
import assistant  # noqa: E402
seen = {}
assistant.ask = lambda q, hist, ctx, role: (seen.update(ctx=ctx, role=role), "Inspection is recommended because of [F3].")[1]
assert OFF.post("/api/assist", json={"question": "Why?", "app_id": "APP-2"}).json()["answer"].endswith("[F3].")
assert seen["role"] == "scrutiny_officer" and any(f["title"] == "Faculty also listed at another college" for f in seen["ctx"]["findings"])
assert INST.post("/api/assist", json={"question": "Why?", "app_id": "APP-2"}).status_code == 403
assert OFF.post("/api/assist", json={"question": "What needs attention?"}).status_code == 200 and "queue" in seen["ctx"]
assert OFF.post("/api/assist", json={"question": " "}).status_code == 422

# national queue: run everything, then cross-college patterns surface
assert APR.post("/api/run-all").json()["checked"] >= 50
rs = {a["id"]: a for a in OFF.get("/api/apps").json()}
assert rs["APP-25"]["outcome"] == "RECOMMEND_INSPECTION"  # college 20 submitted college 19's fire NOC file
f25 = OFF.get("/api/apps/APP-25").json()["run"]["findings"]
assert any(f["check"] == "IDENTICAL_FILE" and "APP-24" in f["message"] for f in f25)
assert any(f["check"] == "LAND_REUSED" for f in OFF.get("/api/apps/APP-32").json()["run"]["findings"])
net = OFF.get("/api/network").json()
assert {"faculty", "file", "land", "photo"} <= {e["kind"] for e in net["edges"]}
queue_names = {n["name"] for n in net["nodes"] if n["app"]}
assert sum(e["kind"] == "faculty" and {e["a"], e["b"]} <= queue_names for e in net["edges"]) >= 4  # a 3-college ring + a pair
assert INST.get("/api/network").status_code == 403

# seeing through edits: every saved version, and a value hidden under an annotation box
revs = OFF.get("/api/apps/APP-2/revisions", params={"doc": "affidavit.pdf"}).json()["revisions"]
assert any(r["signed"] for r in revs) and revs[-1]["after_signing"] and "Approved Intake Declared: 300" in revs[-1]["added"]
assert OFF.get("/api/apps/APP-2/revision.png", params={"doc": "affidavit.pdf", "rev": 1}).content[:4] == b"\x89PNG"
cov = next(f for f in OFF.get("/api/apps/APP-40").json()["run"]["findings"] if f["check"] == "VALUE_COVERED")
assert "30-06-2026" in cov["message"] and "30-06-2028" in cov["message"]

# analyse any document; colleges start drafts and see live norms
an = OFF.post("/api/analyse", files={"file": ("a.pdf", storage.read(gen_data.DATA / "apps" / "APP-2" / "affidavit.pdf"))}).json()
assert an["signature"]["status"] == "changed after signing" and an["revisions"] == 3 and an["seen_in"][0]["app"] == "APP-2"
assert OFF.post("/api/analyse", files={"file": ("x.pdf", b"%PDF-1.4 junk")}).status_code == 422
wi = INST.get("/api/what-if", params={"intake": 240, "faculty": 30, "classrooms": 2}).json()
assert wi["faculty_needed"] == 48 and wi["faculty_short"] == 18 and wi["growth_warning"]
draft = INST.post("/api/apps/new", json={"category": "INCREASE_INTAKE", "proposed_intake": 180, "faculty_count": 36,
                                          "classroom_areas_sqm": [66, 66], "building_age_years": 5}).json()
assert INST.get(f"/api/apps/{draft['id']}").json()["application"]["status"] == "DRAFT"
assert OFF.post("/api/apps/new", json={"category": "INCREASE_INTAKE", "proposed_intake": 1, "faculty_count": 1,
                                        "classroom_areas_sqm": [66], "building_age_years": 1}).status_code == 403

# alerts are routed by role
assert {a["type"] for a in APR.get("/api/alerts").json()} == {"INSPECTION_RECOMMENDED"}
assert "SCAN_TAMPER" in {a["type"] for a in OFF.get("/api/alerts").json()}

# human-only decisions, maker-checker with a real second officer
deny = {"outcome": "ORDER_INSPECTION", "reason": "x", "checker": "officer.k"}
assert AI.post("/api/apps/APP-2/decision", json=deny).status_code == 403
assert OFF.post("/api/apps/APP-2/decision", json=deny).status_code == 403
assert APR.post("/api/apps/APP-2/decision", json=deny).status_code == 409  # HIGH findings still open
assert OFF.post("/api/apps/APP-2/findings/0/review", json={"verdict": "DISMISSED"}).status_code == 422  # dismiss needs reason
assert AI.post("/api/apps/APP-2/findings/0/review", json={"verdict": "ACCEPTED"}).status_code == 403
for f in OFF.get("/api/apps/APP-2").json()["run"]["findings"]:
    OFF.post(f"/api/apps/APP-2/findings/{f['id']}/review", json={"verdict": "ACCEPTED"})
assert OFF.get("/api/apps/APP-2").json()["run"]["findings"][0]["reviewed_by"] == "officer.k"
assert APR.post("/api/apps/APP-2/decision", json={**deny, "checker": "approver.r"}).status_code == 422  # self-check
assert APR.post("/api/apps/APP-2/decision", json={**deny, "checker": "nobody"}).status_code == 422
d = APR.post("/api/apps/APP-2/decision", json=deny).json()
assert d["maker"] == "approver.r" and "record" not in d  # adverse decisions issue no approval record
# maker-checker: only the named second officer, signed in as themself, can confirm or send back
assert d["status"] == "AWAITING_CHECKER"
confirm = lambda c, body: c.post("/api/apps/APP-2/decision/confirm", json=body)
assert confirm(APR, {"agree": True}).status_code == 403
assert confirm(as_("officer.m"), {"agree": True}).status_code == 403
assert "CONFIRM_DECISION" in {a["type"] for a in OFF.get("/api/alerts").json()}
assert confirm(OFF, {"agree": False}).status_code == 422  # sending back needs a reason
assert confirm(OFF, {"agree": False, "note": "Ask for the trust deed first"}).json()["status"] == "SENT_BACK"
assert OFF.get("/api/apps/APP-2").json()["decision"] is None
APR.post("/api/apps/APP-2/decision", json=deny)
assert confirm(OFF, {"agree": True}).json()["status"] == "FINAL"
assert confirm(OFF, {"agree": True}).status_code == 409
pack = APR.get("/api/apps/APP-2/evidence-pack")
assert pack.status_code == 200 and pack.content[:2] == b"PK"

# correction loop: a confirmed deficiency letter reopens the application for exactly the listed items
NAL = as_("1-333333")
for f in OFF.post("/api/apps/APP-3/run").json()["findings"]:
    OFF.post(f"/api/apps/APP-3/findings/{f['id']}/review", json={"verdict": "ACCEPTED"})
APR.post("/api/apps/APP-3/decision", json={"outcome": "ISSUE_DEFICIENCY", "reason": "Missing accounts, unexplained growth", "checker": "officer.k"})
OFF.post("/api/apps/APP-3/decision/confirm", json={"agree": True})
a3 = NAL.get("/api/apps/APP-3").json()["application"]
assert a3["status"] == "RECTIFICATION" and any(i["doc"] == "audited_accounts.pdf" for i in a3["rectification"]["items"])
assert NAL.get("/api/apps/APP-3/letter").content[:4] == b"%PDF"
for doc, name in (("audited_accounts.pdf", "nalanda_audited_accounts.pdf"), ("university_noc.pdf", "nalanda_university_noc.pdf")):
    assert NAL.post("/api/apps/APP-3/documents", data={"doc_type": doc},
                    files={"file": (name, (gen_data.DATA / "inbox" / name).read_bytes(), "application/pdf")}).status_code == 200
NAL.post("/api/apps/APP-3/run")
assert NAL.post("/api/apps/APP-3/submit").json()["status"] == "SUBMITTED"
corr = OFF.post("/api/apps/APP-3/run").json()
assert {i["doc"]: i["fixed"] for i in corr["correction"]["items"]}["audited_accounts.pdf"] is True
assert "CHANGED_OUTSIDE_REQUEST" in {f["check"] for f in corr["findings"]}
noc = next(d for d in corr["correction"]["changed"] if d["doc"] == "university_noc.pdf")
assert not noc["asked"] and {"field": "Proposed Intake", "old": "180", "new": "240"} in noc["fields"]

# approval issues a signed record anyone can check; a forged copy is caught
rec_id = APR.post("/api/apps/APP-1/decision", json={"outcome": "APPROVE"}).json()["record"]
assert anon.get("/api/public/records", params={"q": "vidya"}).json()[0]["id"] == rec_id
assert all(r["institution"] != "Sri Rama Institute of Engineering" for r in anon.get("/api/public/records").json())
original = anon.get(f"/api/public/records/{rec_id}/pdf").content
verdict = lambda data: anon.post("/api/public/verify", files={"file": ("r.pdf", data)}).json()
assert verdict(original)["status"] == "GENUINE"
forged = verdict(gen_data.forge_record(original, "Approved Intake", "300"))
assert forged["status"] == "EDITED_AFTER_SIGNING"
assert forged["differences"] == [{"field": "Approved Intake", "copy": "300", "register": "180"}]
assert verdict((gen_data.DATA / "inbox" / "audited_accounts.pdf").read_bytes())["status"] == "UNSIGNED"
assert verdict(gen_data.sign(original, gen_data.make_pki(gen_data.DATA / "pki_other")))["status"] != "GENUINE"
pki = gen_data.DATA / "pki"  # a college's own DSC chains to the same trusted root, but it is not AICTE's key
college = gen_data.signers.SimpleSigner.load(str(pki / "signer.key"), str(pki / "signer.pem"), ca_chain_files=(str(pki / "ca.pem"),))
assert verdict(gen_data.sign((gen_data.DATA / "inbox" / "audited_accounts.pdf").read_bytes(), college))["status"] == "NOT_AICTE"
assert anon.post("/api/public/verify", files={"file": ("r.pdf", b"%PDF-1.4 junk")}).status_code == 422
assert anon.get("/api/public/records/REC-NOPE").status_code == 404

# norms import: a circular PDF and a JSON export both read back; unknown names are refused; nothing publishes by itself
circ = APR.post("/api/rules/norms/import", files={"file": ("c.pdf", (gen_data.DATA / "inbox" / "norms_circular_2026-27.pdf").read_bytes())}).json()
assert circ["changes"] == [{"programme": "UG Engineering", "norm": "Minimum classroom area (m²)", "from": "66", "to": "50"}]
assert APR.post("/api/rules/norms/import", files={"file": ("n.json", APR.get("/api/rules/norms/export").content)}).json()["changes"] == []
assert APR.post("/api/rules/norms/import", files={"file": ("n.json", b'[{"Programme level": "PhD"}]')}).status_code == 422
assert APR.post("/api/rules/norms/import", files={"file": ("n.json", b'[{"Programme level": "Diploma", "Wifi speed": 5}]')}).status_code == 422
assert OFF.post("/api/rules/norms/import", files={"file": ("n.json", b"[]")}).status_code == 403
assert "AREA_SHORTFALL" in checks_of("APP-2")

# inspection brief, and the post-approval watch when an issuer revokes a certificate
assert OFF.get("/api/inspection-brief", params={"app": "APP-2"}).content[:4] == b"%PDF"
noc = next(r["noc"] for r in OFF.get("/api/issuer/fire").json() if r["app"] == "APP-1")
ev = OFF.post("/api/issuer/fire/revoke", json={"noc": noc}).json()["watch"]
assert ev and ev[0]["app"] == "APP-1"
assert anon.get(f"/api/public/records/{rec_id}").json()["watch"]
assert "WATCH" in {a["type"] for a in APR.get("/api/alerts").json()}

# norms table edit changes the result; a broken table is refused
jdm = json.loads(norms_backup)
assert APR.put("/api/rules/norms", json={"nodes": []}).status_code == 422
jdm["nodes"][1]["content"]["rules"][0]["o0"] = "50"
assert OFF.put("/api/rules/norms", json=jdm).status_code == 403
assert APR.put("/api/rules/norms", json=jdm).status_code == 200
assert "AREA_SHORTFALL" not in checks_of("APP-2")
pramaan.checks.NORMS_FILE.write_text(norms_backup, encoding="utf-8")
pramaan.checks.RULES_FILE.write_text(rules_backup, encoding="utf-8")

# evidence path traversal is refused
assert OFF.get("/api/evidence", params={"app": "APP-1", "doc": "../../pki/signer.key", "kind": "img"}).status_code == 404

# audit chain detects edits; only officers and auditors read it
assert INST.get("/api/audit").status_code == 403
assert AUD.get("/api/audit").json()["chain"]["ok"]
lines = pramaan.AUDIT.read_text().splitlines()
lines[1] = lines[1].replace('"LOGIN"', '"LOGIX"')
pramaan.AUDIT.write_text("\n".join(lines) + "\n")
assert AUD.get("/api/audit").json()["chain"] == {"ok": False, "entries": len(lines), "broken_at": 1}

gen_data.build()  # leave clean demo data behind
print("All checks passed")
