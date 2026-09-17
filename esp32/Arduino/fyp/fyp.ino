#include <WiFi.h>
#include <HTTPClient.h>
#include <esp_task_wdt.h>

const char* ssid       = "Kizo123";
const char* password   = "12345678";
const char* serverURL  = "https://fyp.syedaidid.xyz/api/attacks/";

#define LED_PIN         2     // onboard LED (GPIO2 on most ESP32 boards)
#define MAX_TRACKED_IPS 10
#define SCAN_THRESHOLD  3
#define SCAN_TIME_WINDOW 5000

#define MAX_BANNED_IPS  20
#define BAN_DURATION_MS 600000UL     // 10 minutes
#define BLOCK_LOG_INTERVAL_MS 30000UL // log repeat attempts at most every 30s per IP

WiFiServer telnetServer(23);
WiFiServer httpServer(80);
WiFiServer sshServer(22);

// Silent scan-trap ports — accept & log but never interact. These amplify
// port-scan detection: an IP sweeping several ports trips checkPortScan()
// and gets device-banned almost immediately.
struct TrapPort { int port; WiFiServer server; };
TrapPort trapPorts[] = {
  { 21,   WiFiServer(21)   },   // FTP
  { 443,  WiFiServer(443)  },   // HTTPS/TLS
  { 2323, WiFiServer(2323) },   // alternate telnet (Mirai variant)
  { 5555, WiFiServer(5555) },   // ADB (Android Debug Bridge)
  { 8080, WiFiServer(8080) },   // alternate HTTP admin
};
const int TRAP_COUNT = sizeof(trapPorts) / sizeof(trapPorts[0]);

struct IPTracker {
  String ip;
  int hitCount;
  unsigned long firstHitTime;
};

IPTracker trackedIPs[MAX_TRACKED_IPS];

struct BanEntry {
  String ip;
  unsigned long bannedAt;
  unsigned long lastLogTime;
};

BanEntry bannedIPs[MAX_BANNED_IPS];

// ── LED ──────────────────────────────────────────────────────────────────────

void blinkLED(int times = 3) {
  for (int i = 0; i < times; i++) {
    digitalWrite(LED_PIN, HIGH);
    delay(100);
    digitalWrite(LED_PIN, LOW);
    delay(100);
  }
}

// ── Ingest authentication ────────────────────────────────────────────────────
// Shared secret sent as X-API-Key. MUST equal HONEYPOT_API_KEY on the server.
// Production value (server .env, deployed 2026-09-14):
#define HONEYPOT_API_KEY "7cc37a10fa30ca4da0f5c2cea3ef78bc906e2e0e6b71c8c9"

// ── Payload sanitiser ────────────────────────────────────────────────────────

String sanitise(const String& raw) {
  String out;
  out.reserve(raw.length());
  for (char c : raw) {
    if (c == '"')       out += "'";
    else if (c == '\\') out += "\\\\";
    else if (c >= 32 && c <= 126) out += c;
  }
  return out;
}

// ── Django logger ────────────────────────────────────────────────────────────

void sendToDjango(const String& ip, int port,
                  const String& attackType, const String& payload) {
  if (WiFi.status() != WL_CONNECTED) return;

  // Unique id per event (boot-time millis + counter). Lets the server dedupe
  // retries / double-posts, making ingestion idempotent.
  static unsigned long eventCounter = 0;
  String eventId = String(millis()) + "-" + String(eventCounter++);

  HTTPClient http;
  http.begin(serverURL);
  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-API-Key", HONEYPOT_API_KEY);

  String body = "{\"event_id\":\""     + eventId + "\","
                "\"attacker_ip\":\""   + ip + "\","
                "\"port\":"            + port + ","
                "\"attack_type\":\""   + attackType + "\","
                "\"payload\":\""       + sanitise(payload) + "\","
                "\"sensor\":\"esp32-lan\"}";

  int code = http.POST(body);
  if (code == 403)
    Serial.println("[ERR] 403 — API key mismatch, check HONEYPOT_API_KEY");
  else if (code == 429)
    Serial.println("[WARN] rate limited");
  else if (code == 400)
    Serial.println("[ERR] Django rejected: " + http.getString());
  else
    Serial.println("[LOG] " + attackType + " from " + ip + " → " + code);

  http.end();
  blinkLED();
}

// ── Port scan tracker ────────────────────────────────────────────────────────

bool checkPortScan(const String& ip) {
  unsigned long now = millis();

  for (int i = 0; i < MAX_TRACKED_IPS; i++) {
    if (trackedIPs[i].ip != ip) continue;

    if (now - trackedIPs[i].firstHitTime < SCAN_TIME_WINDOW) {
      trackedIPs[i].hitCount++;
      if (trackedIPs[i].hitCount >= SCAN_THRESHOLD) {
        trackedIPs[i].hitCount    = 0;
        trackedIPs[i].firstHitTime = now;
        return true;
      }
    } else {
      trackedIPs[i].hitCount    = 1;
      trackedIPs[i].firstHitTime = now;
    }
    return false;
  }

  // New IP — find empty slot
  for (int i = 0; i < MAX_TRACKED_IPS; i++) {
    if (trackedIPs[i].ip == "") {
      trackedIPs[i] = { ip, 1, now };
      return false;
    }
  }
  return false; // tracker full, ignore
}

// ── IP ban list (device-level blocking) ──────────────────────────────────────

void addBan(const String& ip) {
  unsigned long now = millis();

  // Already banned → extend the ban window
  for (int i = 0; i < MAX_BANNED_IPS; i++) {
    if (bannedIPs[i].ip == ip) {
      bannedIPs[i].bannedAt = now;
      return;
    }
  }

  // Reuse an empty or already-expired slot
  for (int i = 0; i < MAX_BANNED_IPS; i++) {
    if (bannedIPs[i].ip == "" || now - bannedIPs[i].bannedAt >= BAN_DURATION_MS) {
      bannedIPs[i] = { ip, now, 0 };
      return;
    }
  }
}

// Returns true if ip is currently banned; fills lastLogTime for rate limiting.
bool isBanned(const String& ip, unsigned long& lastLogTime) {
  unsigned long now = millis();
  for (int i = 0; i < MAX_BANNED_IPS; i++) {
    if (bannedIPs[i].ip != ip) continue;
    if (now - bannedIPs[i].bannedAt < BAN_DURATION_MS) {
      lastLogTime = bannedIPs[i].lastLogTime;
      return true;
    }
    bannedIPs[i].ip = ""; // ban expired — free the slot
    return false;
  }
  return false;
}

// Marks a repeat connection from a banned IP as logged (rate limited).
void markBanLogged(const String& ip) {
  for (int i = 0; i < MAX_BANNED_IPS; i++) {
    if (bannedIPs[i].ip == ip) {
      bannedIPs[i].lastLogTime = millis();
      return;
    }
  }
}

// Shared entry point for both services: drop banned IPs immediately and
// record a rate-limited blocking event.
bool rejectIfBanned(WiFiClient& client, int port, const String& ip) {
  unsigned long lastLog = 0;
  if (!isBanned(ip, lastLog)) return false;

  client.stop(); // refuse the connection — no banner, no login prompt

  if (millis() - lastLog >= BLOCK_LOG_INTERVAL_MS) {
    markBanLogged(ip);
    sendToDjango(ip, port, "ip_blocked", "repeat attempt from banned scanner");
  }
  return true;
}

// ── Telnet handler ───────────────────────────────────────────────────────────

void handleTelnet() {
  WiFiClient client = telnetServer.accept();
  if (!client) return;

  String ip = client.remoteIP().toString();

  // Banned IP → drop immediately, no interaction
  if (rejectIfBanned(client, 23, ip)) return;

  if (checkPortScan(ip)) {
    addBan(ip);
    client.stop();
    sendToDjango(ip, 23, "port_scan", "scanner detected — IP banned");
    return;
  }

  client.println("Welcome to IoT Device v1.0");
  client.print("Login: ");

  String received;
  unsigned long timeout = millis() + 5000;
  while (client.connected() && millis() < timeout) {
    if (client.available()) {
      char c = client.read();
      received += c;
      if (c == '\n') break;
    }
  }
  received.trim();

  client.println("\r\nLogin incorrect");
  client.stop();

  sendToDjango(ip, 23,
    received.length() > 0 ? "brute_force" : "connection_attempt",
    received);
}

// ── HTTP handler ─────────────────────────────────────────────────────────────

void handleHTTP() {
  WiFiClient client = httpServer.accept();
  if (!client) return;

  String ip = client.remoteIP().toString();

  // Banned IP → drop immediately, no interaction
  if (rejectIfBanned(client, 80, ip)) return;

  if (checkPortScan(ip)) {
    addBan(ip);
    client.stop();
    sendToDjango(ip, 80, "port_scan", "scanner detected — IP banned");
    return;
  }

  // Read headers
  String request;
  unsigned long timeout = millis() + 3000;
  while (client.connected() && millis() < timeout) {
    if (client.available()) {
      char c = client.read();
      request += c;
      if (request.endsWith("\r\n\r\n")) break;
    }
  }

  // Read POST body if present
  String payload;
  if (request.indexOf("POST") >= 0) {
    timeout = millis() + 2000;
    while (client.available() && millis() < timeout)
      payload += (char)client.read();
  }

  String attackType;
  if      (request.indexOf("POST") >= 0)        attackType = "http_brute_force";
  else if (request.indexOf("GET /admin") >= 0)  attackType = "admin_panel_access";
  else                                           attackType = "http_scan";

  client.print(
  "HTTP/1.1 200 OK\r\n"
  "Content-Type: text/html\r\n\r\n"
  "<!DOCTYPE html><html><head><title>TP-Link Archer Router - Login</title>"
  "<meta name='viewport' content='width=device-width, initial-scale=1'>"
  "<style>"
  "body{margin:0;font-family:Arial,Helvetica,sans-serif;background:#eef1f5;"
  "display:flex;align-items:center;justify-content:center;height:100vh;}"
  ".card{background:#fff;padding:40px 36px;border-radius:6px;"
  "box-shadow:0 2px 10px rgba(0,0,0,0.15);width:320px;text-align:center;}"
  ".logo{font-size:22px;font-weight:bold;color:#2b7de9;margin-bottom:4px;}"
  ".model{font-size:12px;color:#888;margin-bottom:24px;}"
  "input[type=text],input[type=password]{width:100%;padding:10px;margin:8px 0;"
  "border:1px solid #ccc;border-radius:4px;box-sizing:border-box;font-size:14px;}"
  "input[type=submit]{width:100%;padding:10px;margin-top:12px;background:#2b7de9;"
  "color:#fff;border:none;border-radius:4px;font-size:14px;cursor:pointer;}"
  "input[type=submit]:hover{background:#1e63c4;}"
  ".footer{margin-top:20px;font-size:11px;color:#aaa;}"
  "</style></head><body>"
  "<div class='card'>"
  "<div class='logo'>TP-LINK</div>"
  "<div class='model'>Archer C6 &nbsp;|&nbsp; Firmware v1.2.3</div>"
  "<form method='POST' action='/login'>"
  "<input type='text' name='user' placeholder='Username' autocomplete='off'>"
  "<input type='password' name='pass' placeholder='Password' autocomplete='off'>"
  "<input type='submit' value='Log In'>"
  "</form>"
  "<div class='footer'>&copy; TP-Link Technologies Co., Ltd.</div>"
  "</div></body></html>"
);
  client.stop();

  sendToDjango(ip, 80, attackType, payload.length() ? payload : request.substring(0, 80));
}

// ── SSH handler (banner + credential-bait capture) ───────────────────────────

void handleSSH() {
  WiFiClient client = sshServer.accept();
  if (!client) return;

  String ip = client.remoteIP().toString();

  // Banned IP → drop immediately, no interaction
  if (rejectIfBanned(client, 22, ip)) return;

  if (checkPortScan(ip)) {
    addBan(ip);
    client.stop();
    sendToDjango(ip, 22, "port_scan", "scanner detected — IP banned");
    return;
  }

  // Emulate a real OpenSSH banner; clients answer with their own version line
  client.print("SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3\r\n");

  String received;
  unsigned long timeout = millis() + 4000;
  while (client.connected() && millis() < timeout) {
    if (client.available()) {
      char c = client.read();
      received += c;
      if (c == '\n') break;   // client version line is complete
    }
  }
  received.trim();
  if (received.length() > 64) received = received.substring(0, 64);

  client.stop();

  sendToDjango(ip, 22,
    received.length() > 0 ? "brute_force" : "connection_attempt",
    received.length() > 0 ? "SSH client banner: " + received : "SSH connect");
}

// ── Silent scan-trap handler ────────────────────────────────────────────────
// Accepts and immediately closes connections on em-weak ports. No banner is
// ever sent — scanners see an open-but-mute service, and the volume of hits
// across multiple ports is what triggers port-scan detection + device bans.

void handleTraps() {
  for (int i = 0; i < TRAP_COUNT; i++) {
    WiFiClient client = trapPorts[i].server.accept();
    if (!client) continue;

    String ip = client.remoteIP().toString();
    int port = trapPorts[i].port;

    if (rejectIfBanned(client, port, ip)) continue;

    if (checkPortScan(ip)) {
      addBan(ip);
      client.stop();
      sendToDjango(ip, port, "port_scan", "scanner detected — IP banned");
      continue;
    }

    client.stop();
    sendToDjango(ip, port, "connection_attempt", "connect to silent trap port");
  }
}

// ── Setup / Loop ─────────────────────────────────────────────────────────────

void setup() {
  Serial.begin(115200);
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);

  for (auto& t : trackedIPs) t = { "", 0, 0 };
  for (auto& b : bannedIPs)  b = { "", 0, 0 };

  WiFi.begin(ssid, password);
  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
  Serial.println("\nConnected! IP: " + WiFi.localIP().toString());

  WiFi.setSleep(false);
  telnetServer.begin();
  httpServer.begin();
  sshServer.begin();
  for (int i = 0; i < TRAP_COUNT; i++) trapPorts[i].server.begin();

  const esp_task_wdt_config_t wdt = { .timeout_ms = 30000, .idle_core_mask = 0, .trigger_panic = true };
  esp_task_wdt_init(&wdt);
  esp_task_wdt_add(NULL);

  // Startup blink — 5 fast blinks to confirm ready
  blinkLED(5);
  Serial.println("Honeypot active — Ports: 22 (SSH) | 23 (Telnet) | 80 (HTTP) | traps: 21, 443, 2323, 5555, 8080");
}

void loop() {
  esp_task_wdt_reset();

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi lost, reconnecting...");
    WiFi.reconnect();
    delay(3000);
    return;
  }

  handleTelnet();
  handleHTTP();
  handleSSH();
  handleTraps();
}
