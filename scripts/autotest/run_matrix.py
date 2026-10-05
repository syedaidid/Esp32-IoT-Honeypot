#!/usr/bin/env python3
"""
FYP4112 automated test-matrix harness.

  python3 scripts/autotest/run_matrix.py --mode inproc     # Django/API unit+integration (needs Django env)
  python3 scripts/autotest/run_matrix.py --mode external   # TLS, HTTPS redirect, public reachability
  python3 scripts/autotest/run_matrix.py --mode system --disruptive   # Docker stack, decoys, restarts (run ON the VPS)
  python3 scripts/autotest/run_matrix.py --render         # rebuild docs/test_results.md + .csv from all runs

Modes write docs/autotest_<mode>.json; --render merges them into the final
report tables. Test rows created by the harness are tagged [TM] and cleaned up.
"""
import argparse
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
ROOT = HERE.parents[1]
RESULTS = ROOT / "docs"


def cleanup_tagged_rows():
    """Remove any harness-created AttackLog rows.

    Two criteria are used so nothing survives:
      * payload starts with the [TM] marker, and
      * attacker_ip is inside the RFC 5737 TEST-NET blocks the harness uses.
    Rows created by the truncation/length checks carry an untagged filler payload,
    so the IP-range sweep is required as well."""
    try:
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "honeypot.settings")
        import django
        django.setup()
        from django.db.models import Q
        from detector.models import AttackLog
        tagged = AttackLog.objects.filter(payload__startswith="[TM]")
        testnet = AttackLog.objects.filter(
            Q(attacker_ip__startswith="198.51.100.") | Q(attacker_ip__startswith="203.0.113."))
        n1, _ = tagged.delete()
        n2, _ = testnet.delete()
        # throwaway superusers created by the login check
        from django.contrib.auth.models import User
        nu, _ = User.objects.filter(username__startswith="autotest").delete()
        return f"removed {n1} tagged + {n2} TEST-NET rows + {nu} test users"
    except Exception as e:
        return f"cleanup skipped ({type(e).__name__}: {e})"


def run_inproc(disruptive=False, keep=False):
    import report
    from harness import TEST_TAG  # noqa
    import checks_inproc as mod
    rec = report.Recorder("inproc")
    for tid, fn in mod.CHECKS.items():
        rec.execute(tid, fn)
    # tag/cleanup
    if not keep:
        rec.add("CLEANUP", "PASS", cleanup_tagged_rows())
    p = rec.save(RESULTS / "autotest_inproc.json")
    print(f"→ wrote {p} ({len(rec.checks)} checks)")
    return rec


def run_external():
    import report
    import checks_external as mod
    rec = report.Recorder("external")
    for tid, fn in mod.CHECKS.items():
        rec.execute(tid, fn)
    p = rec.save(RESULTS / "autotest_external.json")
    print(f"→ wrote {p} ({len(rec.checks)} checks)")
    return rec


def run_system(disruptive=False):
    import report
    import checks_system as mod
    rec = report.Recorder("system")
    mod.fresh_state()          # clear the sensor's in-RAM ban lists first
    for tid, fn in mod.build(disruptive).items():
        r = rec.execute(tid, fn)
    p = rec.save(RESULTS / "autotest_system.json")
    print(f"→ wrote {p} ({len(rec.checks)} checks)")
    return rec


def render():
    import report
    results = report.load_runs()
    md, csv = report.write_report(results)
    n_pass = sum(1 for c in results.values() if c.status == "PASS")
    n_fail = sum(1 for c in results.values() if c.status == "FAIL")
    print(f"→ wrote {md}\n→ wrote {csv}\n  {n_pass} pass, {n_fail} fail, "
          f"{len(results)} automated checks captured")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["inproc", "external", "system", "all", "render"])
    ap.add_argument("--disruptive", action="store_true",
                    help="allow checks that take the site down (NFT-R02, FT-S10)")
    ap.add_argument("--keep", action="store_true",
                    help="keep [TM]-tagged test rows in the DB")
    args = ap.parse_args()

    if args.mode == "render":
        return render()
    if args.mode in ("inproc", "all"):
        run_inproc(keep=args.keep)
    if args.mode == "external" or args.mode == "all":
        run_external()
    if args.mode == "system" or args.mode == "all":
        run_system(disruptive=args.disruptive)
    if args.mode != "render":
        render()


if __name__ == "__main__":
    main()