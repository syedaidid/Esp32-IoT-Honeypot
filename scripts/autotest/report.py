# Result collection + report rendering (markdown tables + CSV).
import csv
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from spec import ALL_IDS, BY_ID, SECTIONS, SUS_STATEMENTS, UAT_STATEMENTS

ROOT = Path(__file__).resolve().parents[2]          # project root
RESULTS_DIR = ROOT / "docs"


@dataclass
class Check:
    id: str
    status: str          # PASS | FAIL | MANUAL | SKIP | BLOCKED
    actual: str = ""
    note: str = ""
    run: str = ""        # which harness run produced it (inproc/system/external/...)


class SkipCheck(Exception):
    pass


class Recorder:
    """Collects Check results and persists them as JSON for later merging."""

    def __init__(self, run: str = "inproc"):
        self.run = run
        self.checks: list[Check] = []

    def add(self, tid, status, actual="", note=""):
        self.checks.append(Check(tid, status, str(actual)[:400], note, self.run))

    def manual(self, tid, note=""):
        self.add(tid, "MANUAL", "—", note)

    def execute(self, tid, fn, note=""):
        """Run one check function; fn returns (ok, actual), bool, or (None, why)
        where ok=None means SKIP (e.g. a destructive check without --disruptive)."""
        try:
            r = fn()
            ok, actual = r if isinstance(r, tuple) else (bool(r), "" if r else "condition not met")
            if ok is None:
                self.add(tid, "SKIP", "—", actual or note)
            else:
                self.add(tid, "PASS" if ok else "FAIL", actual, note)
        except SkipCheck as e:
            self.add(tid, "SKIP", "—", str(e))
        except Exception as e:
            self.add(tid, "BLOCKED", f"{type(e).__name__}: {e}"[:200], note)

    def save(self, path: Path):
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps([asdict(c) for c in self.checks], indent=1))
        return path


# ── merging multiple run files + rendering ───────────────────────────────────
def load_runs(pattern="autotest_*.json") -> dict[str, Check]:
    """Merge all autotest_<run>.json files → {test_id: best Check}."""
    best: dict[str, Check] = {}
    rank = {"PASS": 4, "FAIL": 3, "BLOCKED": 2, "SKIP": 1, "MANUAL": 0}
    for f in sorted(RESULTS_DIR.glob(pattern)):
        try:
            for d in json.loads(f.read_text()):
                c = Check(**d)
                cur = best.get(c.id)
                if cur is None or rank.get(c.status, 0) > rank.get(cur.status, 0):
                    best[c.id] = c
                elif cur.status == c.status and c.run not in cur.run:
                    cur.note = f"{cur.note} (+{c.run})".strip(" +")
        except Exception:
            continue
    return best


def _row(tid, desc, exp, actual, status):
    esc = lambda s: str(s).replace("|", "\\|").replace("\n", " ")   # keep markdown tables intact
    return f"| {tid} | {esc(desc)} | {esc(exp)} | {esc(actual or '—')} | {status} |"


def render_markdown(results: dict[str, Check]) -> str:
    now = __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M")
    total = len(ALL_IDS)
    counts = {"PASS": 0, "FAIL": 0, "BLOCKED": 0, "SKIP": 0, "MANUAL": 0, "NOT RUN": 0}
    for tid in ALL_IDS:                       # only matrix cases are counted
        st = results.get(tid).status if tid in results else (
            "MANUAL" if BY_ID[tid][3] == "manual" else "NOT RUN")
        counts[st] = counts.get(st, 0) + 1

    human = counts["MANUAL"]
    not_run = counts["NOT RUN"]
    executed = total - human - not_run       # automated cases actually exercised
    passed = counts["PASS"]
    failed = counts["FAIL"] + counts["BLOCKED"] + counts["SKIP"]
    rate = (passed / executed * 100) if executed else 0.0

    out = [
        "# Automated Test Results — FYP4112 ESP32 IoT Honeypot",
        "",
        f"**Generated:** {now} (automated harness `scripts/autotest/`)  ",
        f"**Total test cases:** {total} "
        f"({executed} automated/executed · {human} human-only · {not_run} not yet run)  ",
        f"**Automated results:** {passed} pass · {failed} not pass "
        f"({counts['FAIL']} fail · {counts['BLOCKED']} blocked · {counts['SKIP']} skip)  ",
        f"**Automated pass rate:** {rate:.1f}% ({passed}/{executed} executed cases)  ",
        "> Human-only cases (usability questionnaire + UAT) are not machine-scored; "
        "score them with `score_forms.py` once responses are collected.",
        "",
    ]
    for section, rows in SECTIONS:
        out += [f"## {section}", "",
                "| Test ID | Test Description | Expected Result | Actual Result | Status |",
                "|---|---|---|---|---|"]
        for tid, desc, exp, mode in rows:
            c = results.get(tid)
            if c is None:
                out.append(_row(tid, desc, exp, "—", "MANUAL" if mode == "manual" else "NOT RUN"))
            else:
                actual = c.actual if c.status != "MANUAL" else "—"
                note = f" [{c.note}]" if c.note else ""
                out.append(_row(tid, desc, exp, f"{actual}{note}", c.status))
        out.append("")
        if section.startswith("3."):
            out += ["### 3b. System Usability Scale (1 = Strongly disagree, 5 = Strongly agree)", "",
                    "| # | Statement | Rating (1-5) |", "|---|---|---|"]
            for i, s in enumerate(SUS_STATEMENTS, 1):
                out.append(f"| {i} | {s} | |")
            sus = read_scores()
            if sus:
                out += ["", f"**SUS score: {sus['sus']} / 100** (n = {sus['n']} respondents; "
                        f"> 68 = above average)"]
            out += ["", "SUS scoring: odd statements (rating − 1); even statements (5 − rating); "
                    "sum × 2.5. Automated scoring: `python scripts/autotest/score_forms.py`.", ""]
        if section.startswith("8."):
            out += ["### Overall acceptance (1 = Strongly disagree, 5 = Strongly agree)", "",
                    "| # | Statement | Rating (1-5) |", "|---|---|---|"]
            for i, s in enumerate(UAT_STATEMENTS, 1):
                out.append(f"| {i} | {s} | |")
            if sus and sus.get("uat_n"):
                out += ["", f"**UAT mean acceptance: {sus['uat_mean']} / 5** (n = {sus['uat_n']})"]
            out += ["", "**Final decision:** Accept / Accept with minor changes / Reject", "",
                    "**Open feedback:** What did you like most? What problems did you face? "
                    "What would you improve?", ""]
    return "\n".join(out)


def render_csv(results: dict[str, Check]) -> str:
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["test_id", "description", "expected", "actual", "status"])
    for tid, desc, exp, _ in [(t, BY_ID[t][1], BY_ID[t][2], None) for t in ALL_IDS]:
        c = results.get(tid)
        w.writerow([tid, desc, exp,
                    (c.actual if c and c.status != "MANUAL" else ""),
                    c.status if c else "NOT RUN"])
    return buf.getvalue()


def read_scores() -> dict | None:
    """Merge SUS/UAT scores computed by score_forms.py (if present)."""
    p = RESULTS_DIR / "sus_uat_scores.json"
    if p.exists():
        import json as _j
        return _j.loads(p.read_text())
    return None


def write_report(results: dict[str, Check]):
    md = RESULTS_DIR / "test_results.md"
    csvp = RESULTS_DIR / "test_results.csv"
    md.write_text(render_markdown(results))
    csvp.write_text(render_csv(results))
    return md, csvp