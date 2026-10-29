# Pramaan prototype

Working MVP for SIH 2026 PS 26261. Applications and documents are synthetic. The campus photos are real, licensed photos from Wikimedia Commons (credits in `assets/photos/CREDITS.md`); their GPS and date data is synthetic.

## Run

```bash
pip install fastapi uvicorn python-multipart pymupdf pypdf reportlab imagehash pillow cryptography pyhanko==0.29.0 rapidocr-onnxruntime rapidfuzz zen-engine open_clip_torch torch transformers groq playwright
python gen_data.py
python -m uvicorn app:app --port 8000
```

Then open http://localhost:8000 and sign in. The public check page is http://localhost:8000/check.html (no sign-in).

- The first photo check downloads CLIP ViT-B/32 and Grounding DINO tiny, about 1.3 GB in total. After that, everything runs offline on a CPU.
- Optional: set `GROQ_API_KEY` to let a vision LLM read fields that OCR misses or reads with low confidence.

### Demo accounts (synthetic test accounts, seeded by `gen_data.py`)

| Username | Role | Password |
|---|---|---|
| `officer.k`, `officer.m` | Scrutiny officer | `scrutiny@2026` |
| `approver.r` | Approver (also publishes rules) | `approver@2026` |
| `auditor.v` | Auditor (read-only audit trail) | `auditor@2026` |
| `1-111111` … `1-444444` | Institution (its AICTE ID) | `college@2026` |
| `pramaan-ai` | AI service account, used to show that the AI cannot decide | `service@2026` |

Only PBKDF2 hashes are stored (`data/users.json`). The login page lists the usernames (demo build); passwords are only in this README.

| Command | What it does |
|---|---|
| `python test_pramaan.py` | Self-check: every planted defect, every guard, sign-in, records and rule import (regenerates `data/`) |
| `python bench.py 50 777` | Measured benchmark on a held-out seed → `bench/results.md` |
| `python record_demo.py` | Silent captioned demo video → `demo/pramaan-demo.mp4` |
| `python deck_update.py` | Writes `../SIH-TeamLucipher-v2.pdf` from the Canva deck with updated slides 2, 4, 5 and 6 |

## What makes Pramaan different

1. **A proof level for every claim** (`checks.proof_claims`). Every claim is rated: confirmed by the issuer, matches AICTE records, signed and intact, evidence only, declared only, or contradicted. The application gets a Proof Score and the share that is independently confirmed.
2. **Checks across colleges and years.** Ghost faculty: the same PAN, as a salted hash, on two colleges' lists. Photos reused across colleges. "What changed since the last approval": intake growth that classrooms, faculty and built-up area do not match.
3. **A signed approval record anyone can check** (`records.py`). Approval issues a PDF signed with an AICTE test key, with a QR code. `/check.html` searches the register and verifies an uploaded copy: genuine, edited after signing, unsigned, or not signed by AICTE. It shows the differences from the register.

## What each part really does

| Area | In this MVP | Production path |
|---|---|---|
| Sign-in | PBKDF2 passwords, HMAC-signed HttpOnly session cookie; role and user come only from the session (client headers are dropped) | Portal SSO (Keycloak/OIDC) |
| Intake | Institution uploads (PDF only, max 20 MB, checklist-bound); AICTE portal webhook `POST /api/webhook/application` with a shared token | Same API |
| Storage | Every file is AES-256-GCM encrypted at rest; SHA-256 recorded in the audit log | Key in a KMS/HSM; MinIO |
| Reading | PDF text layer; scanned pages use PP-OCR models via RapidOCR, with bounding boxes; optional Groq vision LLM for weak fields | Qwen2.5-VL self-hosted; Hindi OCR models |
| Rules | GoRules ZEN decision tables for norms and escalation, editable in the UI, importable from a norms circular (PDF) or JSON, versioned; checklists in `rules.json` | Same |
| Consistency | RapidFuzz name/signatory matching tolerant of OCR spacing; date logic; approval history (repeat deficiencies, change since last approval) | Live AICTE records |
| Integrity | DSC validation with pyHanko (detects edits after signing); error-level-analysis heatmap on scans; perceptual-hash duplicate photos; ghost faculty by salted PAN hash | CAT-Net heatmaps; CCA India roots; AICTE faculty portal |
| Sources | Fire registry, DigiLocker (Requester API v1.12 shape), payment gateway: local stand-ins with an outage switch, retries, OCR-tolerant lookup; campus coordinates; six statuses | API Setu / state portals after onboarding |
| Infrastructure | CLIP room-type check, Grounding DINO monitor count, EXIF GPS geofence and photo age, area and faculty norms | Floor-plan area measurement |
| Human control | AI and non-approver roles get 403 on decisions; HIGH findings must be reviewed first; dismissals need a reason; adverse decisions wait until the named second officer confirms them from their own sign-in | Same |
| Records | Approval PDF signed with an AICTE test key (pyHanko), QR to the public check page; register in `data/state.json` | HSM key under CCA India |
| Audit | SHA-256 hash-chained log, including sign-ins; per-application evidence pack (ZIP) | Same |

## Known limits

- **Signature roots:** the test root CA stands in for CCA India, for both institution DSCs and AICTE's record key.
- **Faculty registry:** a synthetic stand-in for AICTE's PAN-linked faculty portal.
- **Tamper threshold:** calibrated on synthetic scans only (clean scans peak at 8–9, edited ones at 17–18).
- **OCR:** RapidOCR's default models drop spaces between words; matching is tolerant of this. No Hindi OCR model yet.
- **Norms circular import:** reads circulars in the "Programme level: … / Norm name: value" layout, not arbitrary APH PDFs.
- **Benchmark:** uses crops of 6 real photos, so photo variety is limited.
