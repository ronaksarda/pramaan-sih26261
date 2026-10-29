"""Measured benchmark: N randomised applications with planted defects and known ground truth.

Run: python bench.py [N]  ->  bench/results.md and bench/results.json
Uses its own data folder (bench_data/), so the demo data is untouched.
"""
import io
import json
import os
import random
import shutil
import statistics
import sys
import time
from collections import Counter
from datetime import date, timedelta
from pathlib import Path

BASE = Path(__file__).parent
os.environ["PRAMAAN_DATA"] = str(BASE / "bench_data")
os.environ["PRAMAAN_CV_CACHE"] = str(BASE / "bench_data" / "cv_cache.json")  # cold photo AI: honest timings

from PIL import Image  # noqa: E402

import checks  # noqa: E402
import gen_data  # noqa: E402

N = int(sys.argv[1]) if len(sys.argv) > 1 else 50
SEED = int(sys.argv[2]) if len(sys.argv) > 2 else 2026  # thresholds were tuned on seed 2026; report other seeds
rnd = random.Random(SEED)
FIRST = ["Aditi", "Rahul", "Meera", "Arjun", "Kavya", "Vikram", "Sneha", "Rohan", "Ananya", "Karthik", "Pooja", "Imran"]
LAST = ["Sharma", "Reddy", "Iyer", "Patil", "Singh", "Nair", "Das", "Khan", "Joshi", "Menon", "Gupta", "Rao"]
PLACE = ["Godavari", "Narmada", "Sahyadri", "Aravalli", "Kaveri", "Ganga", "Krishna", "Tapti", "Mahanadi", "Satpura"]
KIND = ["Institute of Technology", "College of Engineering", "Institute of Engineering", "Engineering College"]
STATES = ["Maharashtra", "Telangana", "Karnataka", "Kerala", "Tamil Nadu", "Gujarat", "Rajasthan", "Odisha"]
LAB, CLASSROOM, LIBRARY = ["lab_b.jpg", "lab_c.jpg"], ["classroom_a.jpg", "classroom_b.jpg", "classroom_c.jpg"], "library_a.jpg"
DEFECTS = {  # defect -> checks it must raise
    "expired_noc": {"DOC_EXPIRED"}, "missing_accounts": {"DOC_MISSING"}, "name_variant": {"NAME_MISMATCH"},
    "wrong_signatory": {"SIGNATORY_MISMATCH"}, "edited_affidavit": {"EDITED_AFTER_SIGNING"},
    "forged_scan": {"SCAN_TAMPER", "SOURCE_MISMATCH"}, "duplicate_photo": {"DUPLICATE_PHOTO"},
    "gps_far": {"GPS_FAR"}, "gps_missing": {"GPS_MISSING"}, "area_short": {"AREA_SHORTFALL"},
    "faculty_short": {"FACULTY_RATIO"}, "oc_not_issued": {"SOURCE_MISMATCH"}, "wrong_scene": {"SCENE_MISMATCH", "EQUIPMENT_LOW"},
    "ghost_faculty": {"GHOST_FACULTY"},  # both colleges listing the same people are flagged
}


def crop(asset, seed):
    """A distinct-looking photo per application: a random 55-70 % window of a real photo, sometimes mirrored."""
    r = random.Random(seed)
    im = Image.open(gen_data.PHOTOS / asset).convert("RGB")
    w, h = im.size
    s = r.uniform(0.55, 0.7)
    x, y = r.randint(0, int(w * (1 - s))), r.randint(0, int(h * (1 - s)))
    im = im.crop((x, y, x + int(w * s), y + int(h * s)))
    if r.random() < 0.5:
        im = im.transpose(Image.FLIP_LEFT_RIGHT)
    name = f"_bench_{seed}_{asset}"
    im.save(gen_data.PHOTOS / name, quality=92)
    return name


def main():
    data = gen_data.DATA
    shutil.rmtree(data, ignore_errors=True)
    signer = gen_data.make_pki(data / "pki")
    registry = {"fire": {}, "ulb": {}, "payments": {}, "digilocker": {}}
    master, specs, truth, temp_photos = {}, [], {}, []
    for i in range(1, N + 1):
        aid = f"2-{i:06d}"
        name = f"{rnd.choice(PLACE)} {rnd.choice(KIND)}"
        master[aid] = {"name": name, "signatory": f"{rnd.choice(FIRST)} {rnd.choice(LAST)}",
                       "lat": round(rnd.uniform(9, 28), 4), "lng": round(rnd.uniform(72, 87), 4),
                       "state": rnd.choice(STATES), "approved_intake": 180, "past_deficiencies": []}
        defects = set() if rnd.random() < 0.3 else set(rnd.sample(sorted(DEFECTS), rnd.randint(1, 3)))
        if {"gps_far", "gps_missing"} <= defects:  # one classroom photo cannot be both
            defects.discard("gps_missing")
        if {"expired_noc", "forged_scan"} <= defects:  # the forged scan shows a valid date; the registry catches it instead
            defects.discard("expired_noc")
        if "duplicate_photo" in defects and i < 3:
            defects.discard("duplicate_photo")
        if "ghost_faculty" in defects and i < 3:
            defects.discard("ghost_faculty")
        lab = crop(rnd.choice(LAB), SEED * 1000 + i * 10 + 1)
        cls = crop(rnd.choice(CLASSROOM), SEED * 1000 + i * 10 + 2)
        temp_photos += [lab, cls]
        photos = [dict(label="lab", file="lab1.jpg", asset=lab, offset=0), dict(label="classroom", file="classroom1.jpg", asset=cls, offset=0)]
        if "duplicate_photo" in defects:
            earlier = rnd.choice(specs[:-1] or specs)
            photos[0] = dict(label="lab", file="lab1.jpg", asset=earlier["photos"][0]["asset"], offset=0, variant=1)
        if "gps_far" in defects:
            photos[1]["offset"] = rnd.choice([0.02, 0.05, 0.1])
        if "gps_missing" in defects:
            photos[1]["offset"] = None if "gps_far" not in defects else photos[1]["offset"]
        if "wrong_scene" in defects:
            photos[0] = dict(label="lab", file="lab1.jpg", asset=crop(LIBRARY, SEED * 1000 + i * 10 + 3), offset=0)
            temp_photos.append(photos[0]["asset"])
        intake = rnd.choice([60, 120, 180])
        spec = dict(id=f"B-{i:03d}", n=i, aicte_id=aid, category="EOA_SELF_DISCLOSURE", proposed_intake=intake,
                    faculty=intake * 4 // (27 if "faculty_short" in defects else rnd.choice([15, 18, 20])),
                    classrooms=[66, 52 if "area_short" in defects else 70], building_age=rnd.randint(3, 25),
                    fire_valid=date(2026, 9, 1) if "expired_noc" in defects else date(2027, 6, 30),
                    submitted_at=f"2026-10-{1 + i // 3:02d}T{10 + i % 3}:00:00", photos=photos,
                    missing=["audited_accounts.pdf"] if "missing_accounts" in defects else [],
                    oc_registered="oc_not_issued" not in defects,
                    fire_name=name.replace("Institute", "Inst.").replace("Engineering", "Engg") + " & Research"
                    if "name_variant" in defects else None,
                    signatory=f"{rnd.choice(FIRST)} {rnd.choice(LAST)}" if "wrong_signatory" in defects else None,
                    tamper_affidavit="edited_affidavit" in defects,
                    scan_fire="forged_scan" in defects or rnd.random() < 0.3,
                    tamper_fire=("Valid Upto", "30-06-2028") if "forged_scan" in defects else None)
        if "ghost_faculty" in defects:
            other = rnd.choice(specs)
            spec.update(ghost_of=other["n"], ghosts=3)
            truth[other["id"]] = sorted(set(truth[other["id"]]) | {"GHOST_FACULTY"})
        if spec["signatory"] and spec["signatory"] == master[aid]["signatory"]:
            spec["signatory"] = "Unknown Person"
        specs.append(spec)
        truth[spec["id"]] = sorted(set().union(*(DEFECTS[d] for d in defects)) if defects else set())
        gen_data.build_app(spec, master, signer, registry, data)
    (data / "master.json").write_text(json.dumps(master, indent=2))
    (data / "registry.json").write_text(json.dumps(registry, indent=2))

    tp, fp, fn, times, rows = Counter(), Counter(), Counter(), [], []
    for s in specs:
        t = time.time()
        found = {f["check"] for f in checks.run(s["id"])["findings"]} - {"DOC_EXPIRING", "FIELD_LOW_CONFIDENCE"}
        times.append(time.time() - t)
        want = set(truth[s["id"]])
        for c in found & want:
            tp[c] += 1
        for c in found - want:
            fp[c] += 1
        for c in want - found:
            fn[c] += 1
        rows.append({"app": s["id"], "expected": sorted(want), "found": sorted(found), "seconds": round(times[-1], 1)})
        print(s["id"], "ok" if found == want else f"expected {sorted(want)} found {sorted(found)}", flush=True)
    for p in temp_photos:
        (gen_data.PHOTOS / p).unlink(missing_ok=True)

    per = {c: {"tp": tp[c], "fp": fp[c], "fn": fn[c],
               "precision": round(tp[c] / (tp[c] + fp[c]), 3) if tp[c] + fp[c] else None,
               "recall": round(tp[c] / (tp[c] + fn[c]), 3) if tp[c] + fn[c] else None}
           for c in sorted(set(tp) | set(fp) | set(fn))}
    T, F, M = sum(tp.values()), sum(fp.values()), sum(fn.values())
    clean = [r for r in rows if not r["expected"]]
    summary = {"applications": N, "clean_applications": len(clean), "planted_defect_checks": T + M,
               "precision": round(T / (T + F), 3), "recall": round(T / (T + M), 3),
               "clean_apps_with_false_flags": sum(bool(r["found"]) for r in clean),
               "apps_fully_correct": sum(set(r["found"]) == set(r["expected"]) for r in rows),
               "median_seconds_per_app": round(statistics.median(times), 1), "max_seconds_per_app": round(max(times), 1),
               "note": "CPU only (no GPU). First application includes model loading. Synthetic documents, real photo crops."}
    out = BASE / "bench"
    out.mkdir(exist_ok=True)
    (out / "results.json").write_text(json.dumps({"summary": summary, "per_check": per, "applications": rows}, indent=2))
    summary["seed"] = SEED
    md = ["# Pramaan benchmark\n", f"{N} randomised applications ({len(clean)} clean), CPU only, seed {SEED}. Generated by "
          "`bench.py`. Thresholds were tuned on seed 2026; other seeds are held out.\n",
          "| Metric | Value |", "|---|---|"] + [f"| {k.replace('_', ' ')} | {v} |" for k, v in summary.items()] + \
         ["", "| Check | TP | FP | FN | Precision | Recall |", "|---|---|---|---|---|---|"] + \
         [f"| {c} | {v['tp']} | {v['fp']} | {v['fn']} | {v['precision']} | {v['recall']} |" for c, v in per.items()]
    (out / "results.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
