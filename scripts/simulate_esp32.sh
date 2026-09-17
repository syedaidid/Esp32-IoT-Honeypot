#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Fake-ESP32 simulator — impersonates the fyp.ino firmware's ingest POSTs so
# the full backend pipeline can be tested without the physical board.
#
# Usage:
#   ./scripts/simulate_esp32.sh            # 5 random events
#   ./scripts/simulate_esp32.sh 20 port_scan   # 20 port_scan events
#
# Env overrides: HONEYPOT_URL, HONEYPOT_API_KEY
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

URL="${HONEYPOT_URL:-http://localhost:8000/api/attacks/}"
KEY="${HONEYPOT_API_KEY:-dev-esp32-honeypot-key}"

COUNT="${1:-5}"
TYPE="${2:-}"

ATTACK_TYPES=(port_scan brute_force connection_attempt http_scan \
              http_brute_force admin_panel_access ip_blocked)
PAYLOADS=(
  "nmap -sS -p 1-10000 192.0.2.1"
  "hydra -l admin -P rockyou.txt ssh"
  "telnet banner grab"
  "dirbuster -u http://192.0.2.1/admin"
  "python3 exploit.py --target admin-login"
  "POST /admin/login.php HTTP/1.1"
  "repeat attempt from banned scanner"
)

send() {
  local ip="$1" port="$2" atype="$3" payload="$4" eid="$5"
  curl -s -o /dev/null -w "  [%{http_code}] $atype from $ip:$port (event=$eid)\n" \
    -X POST "$URL" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $KEY" \
    -d "{\"event_id\":\"$eid\",\"attacker_ip\":\"$ip\",\"port\":$port,\"attack_type\":\"$atype\",\"payload\":\"$payload\"}"
}

echo "Simulating $COUNT event(s) → $URL"
echo

for ((i = 0; i < COUNT; i++)); do
  idx=$((i % ${#ATTACK_TYPES[@]}))
  if [ -n "$TYPE" ]; then atype="$TYPE"; else atype="${ATTACK_TYPES[$idx]}"; fi
  # deterministic pseudo-random noise so dedup/tests stay stable
  octet=$(( (RANDOM % 220) + 2 ))
  port=$((1000 + (RANDOM % 9000)))
  payload="${PAYLOADS[$idx]}"
  eid="$(date +%s%3N)-$i-$$"
  send "192.0.2.$octet" "$port" "$atype" "$payload" "$eid"
done

echo
echo "Done. Browser: http://localhost:8000  (login: admin)"