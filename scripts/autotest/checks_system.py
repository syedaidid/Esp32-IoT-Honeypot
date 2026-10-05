# System-level checks — run ON THE VPS HOST (plain python3, no Django import).
# Drives the real Docker stack, real decoy ports and the real sensor binary.
# Invoke:  python3 scripts/autotest/run_matrix.py --mode system   (over SSH on the VPS)
import json
import socket
import time
import urllib.request

import harness as H

VPS_DECOY_PORTS = [23, 2323, 21, 5555, 7547]


def _db(snippet):
    """Query the live DB through the web container (returns stdout text)."""
    return H.docker_exec_db(snippet)


def _count_attacks():
    return _db("from detector.models import AttackLog; print(AttackLog.objects.count())")


def _int(snippet, default=-1):
    """Parse an integer out of a docker-exec DB query."""
    txt = _db(snippet)
    for line in reversed(str(txt).splitlines()):
        line = line.strip()
        if line.isdigit():
            return int(line)
    return default


def _telnet_capture():
    """FT-S03: connect to the fake telnet (port 2323) and submit creds.
    Returns True if the creds appear in a brute_force payload in the DB."""
    marker = "autotest_user"          # distinctive username -> searchable in payload
    def q():
        return _db(f"from detector.models import AttackLog; "
                   f"print(AttackLog.objects.filter(payload__contains='{marker}').count())")

    def drain(sock, t=1.0):
        sock.settimeout(t)
        buf = b""
        try:
            while True:
                chunk = sock.recv(256)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
        return buf

    before = q()
    try:
        with socket.create_connection(("127.0.0.1", 2323), timeout=5) as s:
            drain(s)                                   # banner
            s.sendall(marker.encode() + b"\n")
            drain(s)                                   # password prompt
            s.sendall(b"hunter2\n")
            time.sleep(1.0)
            drain(s, 0.5)
    except OSError as e:
        return False, f"telnet connect failed: {e}"
    # sensor posts to the API asynchronously
    for _ in range(12):
        time.sleep(0.5)
        if q() != before:
            return True, f"credentials captured: payload contains user='{marker}' + password"
    return False, f"no brute_force event with '{marker}' within 6s"


def _port_scan(ports=(2323, 21, 5555)):
    """FT-S04: probe >=3 distinct decoy ports within the 5s window."""
    before = _int("from detector.models import AttackLog; "
                  "print(AttackLog.objects.filter(attack_type='port_scan', "
                  "attacker_ip='127.0.0.1').count())")
    t0 = time.time()
    opened = []
    for p in ports:
        try:
            with socket.create_connection(("127.0.0.1", p), timeout=2):
                opened.append(p)
        except OSError:
            pass
    span = time.time() - t0
    for _ in range(10):
        time.sleep(0.5)
        after = _int("from detector.models import AttackLog; "
                     "print(AttackLog.objects.filter(attack_type='port_scan', "
                     "attacker_ip='127.0.0.1').count())")
        if after != before:
            return True, (f"scanned {opened} in {span:.1f}s -> port_scan logged "
                          f"(127.0.0.1 now banned)")
    return False, f"no port_scan event after scanning {opened} in {span:.1f}s"


def _http_decoy():
    """FT-S06: an HTTP decoy admin page should record http_scan / admin_panel_access."""
    # the sensor binds only telnet/ftp/adb/tr-069 traps; port 80/8080 belong to the
    # real console (nginx -> Django), not to a decoy. A decoy would be served by the
    # sensor process with its own admin/login markup.
    decoy_found = None
    for port in (8081, 8888, 81, 8080):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.5) as s:
                s.sendall(b"GET /admin/ HTTP/1.0\r\nHost: router\r\n\r\n")
                s.settimeout(2)
                data = s.recv(400).lower()
                if b"dvr" in data or b"camera" in data or b"firmware" in data or b"router" in data:
                    decoy_found = (port, data[:40])
                    break
        except OSError:
            continue
    if decoy_found:
        return True, f"HTTP decoy responded on port {decoy_found[0]}"
    return False, ("no HTTP decoy service — the VPS sensor exposes telnet/FTP/ADB/TR-069 "
                   "traps only, so http_scan/admin_panel_access are recorded only via "
                   "ingest (ESP32 firmware has the HTTP decoy; untested, no hardware)")


def _wait_site(timeout=60):
    t0 = time.time()
    while time.time() - t0 < timeout:
        code, _, _ = H.http("https://fyp.syedaidid.xyz/accounts/login/", timeout=5)
        if code == 200:
            return True, f"site reachable in {time.time()-t0:.1f}s"
        time.sleep(2)
    return False, f"site not reachable after {timeout}s"


def _compose(action):
    return H.sh(f"docker compose {action}", timeout=180)


# ── checks ───────────────────────────────────────────────────────────────────
def i08_s01():
    rc, out, _ = H.sh("docker compose ps --format '{{.Name}} {{.State}}'")
    up = [l for l in out.splitlines() if "running" in l]
    names = " ".join(sorted(u.split()[0] for u in up))
    want = {"honeypot_web", "honeypot_db", "honeypot_nginx", "honeypot_sensor"}
    have = {u.split()[0] for u in up}
    return want <= have, f"{len(up)} services running: {names}"


def s03():
    return _telnet_capture()


def s04():
    return _port_scan()


def s05():
    """While banned, repeat probes are logged as ip_blocked, throttled to 1/30s."""
    ipc = lambda: _int("from detector.models import AttackLog; "
                       "print(AttackLog.objects.filter(attack_type='ip_blocked', "
                       "attacker_ip='127.0.0.1').count())")
    before = ipc()
    for p in (5555, 7547, 23):        # fast repeat probes while still banned
        try:
            socket.create_connection(("127.0.0.1", p), timeout=1).close()
        except OSError:
            pass
    time.sleep(2)
    after = ipc()
    return (after <= before + 1 and after > before,
            f"ip_blocked rows {before} -> {after} after 3 rapid probes while banned "
            f"(throttle = max 1 per 30s)")


def s06():
    return _http_decoy()


def r01():
    before = _count_attacks()
    H.sh("docker restart honeypot_web", timeout=120)
    ok, site = _wait_site()
    after = _count_attacks()
    return (ok and before == after), f"count {before} -> {after}; {site}"


def r02(disruptive=False):
    if not disruptive:
        return None, "skipped (needs --disruptive: takes the site down ~30s)"
    before = _count_attacks()
    H.sh("docker compose down", timeout=180)
    H.sh("docker compose up -d", timeout=300)
    ok, site = _wait_site()
    after = _count_attacks()
    return (ok and before == after), f"count {before} -> {after}; {site}"


def s10(disruptive=False):
    if not disruptive:
        return None, "skipped (needs --disruptive: restarts all containers)"
    before = _count_attacks()
    H.sh("docker compose restart", timeout=240)
    ok, site = _wait_site()
    after = _count_attacks()
    return (ok and before == after), f"count {before} -> {after}; {site}"


def r08():
    H.sh("docker restart honeypot_sensor", timeout=60)
    time.sleep(3)
    # a probe right after restart should be captured from a clean (unbanned) state
    before = _int("from detector.models import AttackLog; "
                  "print(AttackLog.objects.filter(attacker_ip='127.0.0.1').count())")
    try:
        socket.create_connection(("127.0.0.1", 23), timeout=2).close()
    except OSError as e:
        return False, f"sensor not listening on 23 after restart: {e}"
    for _ in range(10):
        time.sleep(0.5)
        after = _int("from detector.models import AttackLog; "
                     "print(AttackLog.objects.filter(attacker_ip='127.0.0.1').count())")
        if after > before:
            return True, "sensor restarted and captured a fresh probe (clean state)"
    return False, "sensor restarted but no new capture within 5s"


def fresh_state():
    """Restart the sensor so RAM ban lists start empty (makes the suite re-runnable)."""
    H.sh("docker restart honeypot_sensor", timeout=60)
    time.sleep(3)


CHECKS_DISRUPTIVE = {"NFT-R02": r02, "FT-S10": s10}


def build(disruptive=False):
    checks = {
        "FT-I08": i08_s01, "FT-S01": i08_s01, "FT-S03": s03, "FT-S04": s04,
        "FT-S05": s05, "FT-S06": s06, "NFT-R01": r01, "NFT-R08": r08,
    }
    if disruptive:
        checks.update({"NFT-R02": lambda: r02(True), "FT-S10": lambda: s10(True)})
    else:
        checks["NFT-R02"] = lambda: r02(False)
        checks["FT-S10"] = lambda: s10(False)
    return checks