#!/usr/bin/env python3
"""
Scores the human-collected questionnaires:

  SUS (Section 3b):  docs/sus_responses.csv  — one row per respondent, 10 columns
                     q1..q10, ratings 1-5. Output: 0-100 SUS score.
  UAT (Section 8):   docs/uat_responses.csv  — one row per respondent, columns
                     task_id (UAT-01..09), value (PASS/FAIL), plus optional
                     uat1..uat6 overall-acceptance ratings.

  python3 scripts/autotest/score_forms.py
"""
import csv
import json
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"


def read_csv(path):
    if not path.exists():
        return None
    with path.open() as f:
        return list(csv.DictReader(f))


def score_sus():
    rows = read_csv(DOCS / "sus_responses.csv")
    if not rows:
        return None, 0, None
    scores = []
    for r in rows:
        try:
            ratings = [int(r[f"q{i}"]) for i in range(1, 11)]
        except (KeyError, ValueError):
            continue
        contrib = [(ratings[i] - 1) if i % 2 == 0 else (5 - ratings[i])
                   for i in range(10)]
        scores.append(sum(contrib) * 2.5)
    return round(statistics.mean(scores), 1) if scores else None, len(scores), scores


def score_uat():
    rows = read_csv(DOCS / "uat_responses.csv")
    if not rows:
        return None, None, None
    n = len(rows)
    tasks = {}
    for r in rows:
        tid = (r.get("task_id") or "").strip()
        val = (r.get("value") or "").strip().upper()
        if tid:
            tasks.setdefault(tid, []).append(val)
    task_pass = {t: sum(1 for v in vs if v == "PASS") / len(vs) for t, vs in tasks.items()}
    overall = [v for vs in tasks.values() for v in vs]
    rate = sum(1 for v in overall if v == "PASS") / len(overall) if overall else None
    # overall acceptance statements uat1..uat6
    accept = []
    for r in rows:
        vals = []
        for i in range(1, 7):
            try:
                vals.append(int(r[f"uat{i}"]))
            except (KeyError, ValueError):
                pass
        if vals:
            accept.append(statistics.mean(vals))
    mean_accept = round(statistics.mean(accept), 2) if accept else None
    return (round(rate * 100, 1) if rate is not None else None), n, \
        {"per_task_pass_rate": task_pass, "acceptance_mean": mean_accept}


def main():
    sus, n_sus, _ = score_sus()
    uat_rate, n_uat, uat_detail = score_uat()
    out = {"sus": sus, "n": n_sus,
           "uat_pass_rate_pct": uat_rate, "uat_n": n_uat,
           "uat_mean": (uat_detail or {}).get("acceptance_mean") if uat_detail else None}
    DOCS.mkdir(exist_ok=True)
    (DOCS / "sus_uat_scores.json").write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))
    if sus is not None:
        verdict = "above average" if sus > 68 else ("marginal" if sus >= 50 else "below average")
        print(f"\nSUS score: {sus} / 100 ({verdict}; n={n_sus})")
    if uat_rate is not None:
        print(f"UAT task pass rate: {uat_rate}% (n={n_uat} respondents)")


if __name__ == "__main__":
    main()