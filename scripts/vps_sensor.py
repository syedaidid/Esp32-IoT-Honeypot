#!/usr/bin/env python3
"""
VPS sensor — internet-facing decoy ports that report into the Hive Sentinel
backend through the same /api/attacks/ ingest as the ESP32 LAN sensor.

Decoys (mirroring the ESP32 firmware):
  23   telnet   — fake login banner, captures credentials
  2323 telnet2  — alternate telnet (Mirai favourite)
  21   ftp      — banner only
  5555 adb      — silent trap (Android Debug Bridge)
  7547 tr-069   — silent trap (router management, Mirai target)

Behaviour:
  - port-scan detection: >=3 distinct ports within 5s from one IP
  - brute-force detection: >=3 login failures within 60s from one IP
  - device ban: 10 min (repeat attempts logged at most every 30s)
  - HTTPS POST with X-API-Key + unique event_id (server dedupes)

Run:  python3 vps_sensor.py --url https://fyp.syedaidid.xyz/api/attacks/ --key <KEY>
"""
import argparse
import asyncio
import json
import ssl
import sys
import time
import urllib.request
import uuid
from collections import defaultdict

# ── tunables ────────────────────────────────────────────────────────────────
SENSOR_ID = 'vps-sensor'
SCAN_WINDOW = 5.0        # seconds
SCAN_THRESHOLD = 3       # distinct ports in window → port_scan
BRUTE_WINDOW = 60.0
BRUTE_THRESHOLD = 3
BAN_MS = 600             # seconds (10 min)
BLOCK_LOG_INTERVAL = 30  # seconds per banned IP

DECOY_PORTS = [23, 2323, 21, 5555, 7547]  # default (VPS, root)
LOCAL_PORTS = [9023, 9323, 9021, 9555, 9547]  # unprivileged equivalents (local dev)

BANNERS = {
    23:   b"\xff\xfd\x01\xff\xfd\x03\xff\xfc\x22\r\nESP32 login: ",
    2323: b"\r\nWelcome to ESP32 telnet\r\nLogin: ",
    21:   b"220 ESP32 FTP server ready.\r\n",
    5555: b"",   # silent traps
    7547: b"",
}


class State:
    def __init__(self):
        self.port_hits = defaultdict(list)     # ip -> [(port, t)]
        self.login_fails = defaultdict(list)   # ip -> [t]
        self.banned = {}                       # ip -> (banned_at, last_logged)
        self.event_seq = 0
        self.lock = asyncio.Lock()

    def next_event_id(self):
        self.event_seq += 1
        return f"{SENSOR_ID}-{int(time.time()*1000)}-{self.event_seq}-{uuid.uuid4().hex[:6]}"


state = State()


# ── backend POST ─────────────────────────────────────────────────────────────
def post_event(attacker_ip, port, attack_type, payload, url, key, insecure):
    body = json.dumps({
        'event_id': state.next_event_id(),
        'attacker_ip': attacker_ip,
        'port': port,
        'attack_type': attack_type,
        'payload': payload[:500],
        'sensor': SENSOR_ID,
    }).encode()
    req = urllib.request.Request(url, data=body, headers={
        'Content-Type': 'application/json',
        'X-API-Key': key,
    })
    ctx = ssl._create_unverified_context() if insecure else None
    try:
        with urllib.request.urlopen(req, timeout=6, context=ctx) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception as e:
        code = 0
    print(f"[LOG] {attack_type} from {attacker_ip}:{port} -> {code}", flush=True)


async def send_event(ip, port, atype, payload, url, key, insecure):
    await asyncio.to_thread(post_event, ip, port, atype, payload, url, key, insecure)


# ── detection logic ──────────────────────────────────────────────────────────
def is_banned(ip):
    ent = state.banned.get(ip)
    if not ent:
        return False
    banned_at, _ = ent
    if time.time() - banned_at > BAN_MS:
        del state.banned[ip]
        return False
    return True


async def check_port_scan(ip, port, url, key, insecure):
    now = time.time()
    hits = state.port_hits[ip]
    hits.append((port, now))
    state.port_hits[ip] = [(p, t) for p, t in hits if now - t < SCAN_WINDOW]
    distinct = {p for p, _ in state.port_hits[ip]}
    if len(distinct) >= SCAN_THRESHOLD and not is_banned(ip):
        state.banned[ip] = (now, 0.0)
        await send_event(ip, port, 'port_scan', f'scanner detected — {len(distinct)} ports in {SCAN_WINDOW:.0f}s — IP banned', url, key, insecure)
        await send_event(ip, port, 'ip_blocked', f'banned for {BAN_MS//60} min after scan', url, key, insecure)


async def check_brute(ip, port, url, key, insecure):
    now = time.time()
    fails = state.login_fails[ip]
    fails.append(now)
    state.login_fails[ip] = [t for t in fails if now - t < BRUTE_WINDOW]
    if len(state.login_fails[ip]) >= BRUTE_THRESHOLD and not is_banned(ip):
        state.banned[ip] = (now, 0.0)
        await send_event(ip, port, 'brute_force', f'{len(state.login_fails[ip])} failed logins in {BRUTE_WINDOW:.0f}s — IP banned', url, key, insecure)
        await send_event(ip, port, 'ip_blocked', f'banned for {BAN_MS//60} min after brute force', url, key, insecure)


# ── per-connection handler ─────────────────────────────────────────────────
async def handle_conn(reader, writer, port, url, key, insecure):
    peer = writer.get_extra_info('peername')[0]
    try:
        if is_banned(peer):
            ent = state.banned[peer]
            if time.time() - ent[1] > BLOCK_LOG_INTERVAL:
                state.banned[peer] = (ent[0], time.time())
                await send_event(peer, port, 'ip_blocked', 'repeat attempt from banned source', url, key, insecure)
            return

        await check_port_scan(peer, port, url, key, insecure)
        if is_banned(peer):
            return

        if port in (23, 2323):
            # telnet: interactive-ish banner → credential capture
            banner = BANNERS[port]
            writer.write(banner)
            await writer.drain()
            try:
                user = (await asyncio.wait_for(reader.read(128), timeout=10) or b'').decode('utf-8', 'replace').strip()
                if user:
                    writer.write(b"Password: ")
                    await writer.drain()
                    pw = (await asyncio.wait_for(reader.read(128), timeout=10) or b'').decode('utf-8', 'replace').strip()
                    if pw:
                        await send_event(peer, port, 'brute_force',
                                         f'login attempt user={user!r} pass={pw!r}', url, key, insecure)
                        await check_brute(peer, port, url, key, insecure)
                        return
            except (asyncio.TimeoutError, ConnectionResetError):
                pass
            await send_event(peer, port, 'connection_attempt', 'telnet connect, no login', url, key, insecure)

        elif port == 21:
            writer.write(BANNERS[21])
            await writer.drain()
            await asyncio.sleep(0.4)
            await send_event(peer, port, 'connection_attempt', 'ftp banner grab', url, key, insecure)

        else:
            # silent traps (5555 adb, 7547 tr-069)
            await send_event(peer, port, 'connection_attempt', 'connect to silent trap port', url, key, insecure)

    except ConnectionResetError:
        pass
    except Exception as e:
        print(f"[ERR] {e}", file=sys.stderr, flush=True)
    finally:
        try:
            writer.close()
        except Exception:
            pass


# ── main ─────────────────────────────────────────────────────────────────────
async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--url', required=True, help='ingest endpoint, e.g. https://fyp.syedaidid.xyz/api/attacks/')
    ap.add_argument('--key', required=True, help='HONEYPOT_API_KEY shared secret')
    ap.add_argument('--insecure', action='store_true', help='skip TLS verification (self-signed dev)')
    ap.add_argument('--local-ports', action='store_true',
                    help='bind unprivileged decoy ports (>=1024) for local dev without root')
    args = ap.parse_args()

    ports = LOCAL_PORTS if args.local_ports else DECOY_PORTS

    servers = []
    for port in ports:
        srv = await asyncio.start_server(
            lambda r, w, p=port: handle_conn(r, w, p, args.url, args.key, args.insecure),
            host='0.0.0.0', port=port)
        servers.append(srv)
        print(f"[BOOT] listening on 0.0.0.0:{port}", flush=True)

    print(f"[BOOT] {SENSOR_ID} active — decoys: {ports}", flush=True)
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[EXIT] sensor stopped", flush=True)