# Shared helpers for the harness: HTTP (stdlib only — no new deps in prod),
# TLS inspection, docker/system calls, and sensor-rule testing utilities
# (fake clock so the 10-minute ban expiry is verified in milliseconds).
import json
import shlex
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST_TAG = "[TM]"            # payload marker for all harness-created rows
TEST_IPS = ["198.51.100.%d" % i for i in range(10, 20)] + \
           ["203.0.113.%d" % i for i in range(10, 20)]


# ── HTTP ─────────────────────────────────────────────────────────────────────
def http(url, data=None, headers=None, method=None, timeout=15, verify=True):
    """Return (status, body_bytes, elapsed_seconds). Never raises on HTTP status."""
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    ctx = None if verify else ssl._create_unverified_context()
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(), time.time() - t0
    except urllib.error.HTTPError as e:
        return e.code, e.read(), time.time() - t0
    except Exception as e:
        return 0, str(e).encode(), time.time() - t0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Stop at the first response so redirects can be asserted."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_nofollow(url, timeout=10, headers=None):
    """Return (status, headers) WITHOUT following redirects."""
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers)
    except Exception as e:
        return 0, {"error": str(e)}


def http_json(url, obj, headers=None, method="POST", timeout=15):
    body = json.dumps(obj).encode()
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    return http(url, data=body, headers=h, method=method, timeout=timeout)


def tls_info(host="fyp.syedaidid.xyz", port=443):
    """Return dict of certificate facts (validates the chain by default)."""
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            cert = ss.getpeercert()
    return {
        "subject": dict(x[0] for x in cert.get("subject", [])),
        "issuer": dict(x[0] for x in cert.get("issuer", [])),
        "not_after": cert.get("notAfter"),
        "not_before": cert.get("notBefore"),
    }


def host_gateway_for_ports(ports=(23, 2323)):
    """In a container, find the docker bridge gateway that reaches host decoy ports."""
    for gw in ["172.17.0.1", "172.18.0.1", "172.19.0.1", "172.20.0.1", "172.21.0.1"]:
        if all(_tcp_open(gw, p, timeout=1) for p in ports):
            return gw
    return None


def _tcp_open(host, port, timeout=2):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ── docker / system (host mode) ──────────────────────────────────────────────
def sh(cmd, timeout=180, check=False):
    p = subprocess.run(shlex.split(cmd) if isinstance(cmd, str) else cmd,
                       capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"cmd failed: {cmd}\n{p.stderr[-300:]}")
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def docker_exec_db(sql_like):
    """Run a Django shell snippet inside honeypot_web and return its LAST output
    line (strips the 'N objects imported automatically' banner)."""
    code = f'python manage.py shell -c "{sql_like.replace(chr(34), chr(39))}"'
    rc, out, err = sh(["docker", "exec", "honeypot_web"] + shlex.split(code))
    if rc != 0:
        return f"ERR:{err[-200:]}"
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    return lines[-1] if lines else ""


# ── sensor-rule testing (import the real sensor module, fake the clock) ─────
def load_sensor():
    """Import scripts/vps_sensor.py from the project root."""
    import importlib.util
    path = ROOT / "scripts" / "vps_sensor.py"
    spec = importlib.util.spec_from_file_location("vps_sensor", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeClock:
    """Monkeypatch time.time inside a module so ban expiry can be tested instantly."""
    def __init__(self, mod, start=None):
        self.mod = mod
        self.t = start if start is not None else time.time()
        self._orig = mod.time.time
        mod.time.time = lambda: self.t
    def advance(self, seconds):
        self.t += seconds
    def restore(self):
        self.mod.time.time = self._orig


def new_event_id():
    return "autotest-%s" % uuid.uuid4().hex[:16]