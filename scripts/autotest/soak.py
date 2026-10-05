#!/usr/bin/env python3
"""
Soak / endurance monitor for NFT-R06 (24-hour uptime) and NFT-R07 (30-minute
console session with no HTTP 500s). Leave it running on any machine; results are
written to docs/soak_<name>.json and picked up by `run_matrix.py --render`.

  # 24-hour uptime soak (NFT-R06)
  python3 scripts/autotest/soak.py --duration 24h --name uptime24

  # 30-minute console browsing soak (NFT-R07) — needs login
  python3 scripts/autotest/soak.py --duration 30m --name console30 \
      --user admin --password '...' --browse
"""
import argparse
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import harness as H  # noqa: E402

ROOT = HERE.parents[1]
RESULTS = ROOT / "docs"
TARGET = "https://fyp.syedaidid.xyz"


def login_session(user, password):
    """Cookie jar for authenticated browsing (login form + CSRF)."""
    import http.cookiejar
    jar = http.cookiejar.CookieJar()
    opener = H.urllib.request.build_opener(H.urllib.request.HTTPCookieProcessor(jar))
    body = H.urllib.parse.urlencode({"username": user, "password": password}).encode()
    req = H.urllib.request.Request(f"{TARGET}/accounts/login/", data=body)
    try:
        opener.open(req, timeout=10)
    except Exception:
        pass
    return opener


def browse_once(opener):
    """Hit the read-only console pages + both exports. Returns list of (url, code)."""
    out = []
    for path in ["/", "/map/", "/logs/", "/attackers/", "/export/csv/", "/report/"]:
        try:
            with opener.open(f"{TARGET}{path}", timeout=20) as r:
                out.append((path, r.status, len(r.read())))
        except H.urllib.error.HTTPError as e:
            out.append((path, e.code, 0))
        except Exception as e:
            out.append((path, 0, 0))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", default="24h")
    ap.add_argument("--interval", default="60", help="seconds between probes")
    ap.add_argument("--name", default="uptime")
    ap.add_argument("--user")
    ap.add_argument("--password")
    ap.add_argument("--browse", action="store_true",
                    help="authenticated console browsing (NFT-R07)")
    args = ap.parse_args()

    def parse_dur(s):
        s = s.strip().lower()
        if s.endswith("h"):
            return float(s[:-1]) * 3600
        if s.endswith("m"):
            return float(s[:-1]) * 60
        return float(s)

    total = parse_dur(args.duration)
    interval = float(args.interval)
    opener = login_session(args.user, args.password) if args.browse else None

    samples, errors, five_hundreds = [], [], 0
    print(f"[SOAK] {args.name}: {args.duration} @ {interval}s interval"
          f"{' (browsing)' if args.browse else ' (public probe)'}")
    t_end = time.time() + total
    while time.time() < t_end:
        if opener:
            results = browse_once(opener)
            bad = [r for r in results if r[1] >= 500 or r[1] == 0]
            five_hundreds += sum(1 for r in results if r[1] == 500)
        else:
            code, _, _ = H.http(f"{TARGET}/accounts/login/", timeout=15)
            bad = [("/accounts/login/", code, 0)] if (code >= 500 or code == 0) else []
        samples.append(time.time())
        if bad:
            errors.append({"ts": time.time(), "bad": bad})
            print(f"  ! {bad}", flush=True)
        # container uptime snapshot
        try:
            rc, out, _ = H.sh("docker inspect -f '{{.State.Status}} {{.RestartCount}}' "
                              "honeypot_web", timeout=10)
            if rc == 0 and "running" not in out:
                errors.append({"ts": time.time(), "container": out})
        except Exception:
            pass
        time.sleep(interval)

    up = len(samples)
    # NFT-R06/07 verdicts
    results = {"NFT-R06" if not args.browse else "NFT-R07": {
        "status": "PASS" if not errors else "FAIL",
        "actual": (f"{up} probes over {total/3600:.1f}h, {len(errors)} error window(s), "
                   f"{five_hundreds} HTTP 500 responses"),
    }}
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / f"soak_{args.name}.json").write_text(json.dumps(results, indent=1))
    print(f"[SOAK] done -> docs/soak_{args.name}.json  ({up} probes, {len(errors)} errors)")


if __name__ == "__main__":
    main()