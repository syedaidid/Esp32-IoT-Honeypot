# Canonical test matrix (FYP4112 test plan). Single source of truth for the
# harness + the generated report tables (Test ID | Description | Expected |
# Actual | Status). Descriptions mirror the approved test plan verbatim.
#
# mode: 'auto'    → the harness executes it
#       'manual'  → needs a human participant / observation (blank by design)
#       'soak'    → executed by soak.py over time (result picked up from JSON)

SECTIONS = [
    ("1. Non-Functional: Performance Testing (NFT-P)", [
        ("NFT-P01", "Load the SOC dashboard (stat bar, 24-hour chart, threat doughnut) under normal conditions", "Page loads within 5 seconds", "auto"),
        ("NFT-P02", "Load the threat map page with attacker markers", "Page loads within 5 seconds", "auto"),
        ("NFT-P03", "Leave the dashboard open for 30 seconds and observe the 10-second auto-refresh", "Data refreshes about every 10 seconds without a page reload or freeze", "auto"),
        ("NFT-P04", "Open the attack log when it holds 1,000+ events", "Page responds within 5 seconds", "auto"),
        ("NFT-P05", "Export the PDF forensic report", "Report is generated within 10 seconds", "auto"),
        ("NFT-P06", "Export the CSV report", "File is generated within 5 seconds", "auto"),
        ("NFT-P07", "Send 60 valid requests in one minute to /api/attacks/ from one IP", "All 60 requests are accepted (HTTP 2xx)", "auto"),
        ("NFT-P08", "Send a 61st request within the same minute", "Request is rejected with HTTP 429", "auto"),
        ("NFT-P09", "Probe 3 different ports on the sensor within 5 seconds", "Detected as port_scan and the IP is banned within 5 seconds", "auto"),
    ]),
    ("2. Non-Functional: Security Testing (NFT-S)", [
        ("NFT-S01", "Send POST /api/attacks/ without an X-API-Key header", "Request is rejected (HTTP 401/403) and nothing is stored", "auto"),
        ("NFT-S02", "Send POST /api/attacks/ with a wrong API key", "Request is rejected and nothing is stored", "auto"),
        ("NFT-S03", "Send more than 60 requests in one minute from one IP", "Extra requests are rejected with HTTP 429", "auto"),
        ("NFT-S04", "Send the same event_id twice", "Second request is ignored; only one record is stored", "auto"),
        ("NFT-S05", "Send an event with an invalid IP (e.g. 999.1.1.1)", "Request is rejected with a validation error", "auto"),
        ("NFT-S06", "Send an event with port 70000", "Request is rejected with a validation error", "auto"),
        ("NFT-S07", "Send an event with sensor ID \"fake-sensor\"", "Request is rejected (not in the sensor whitelist)", "auto"),
        ("NFT-S08", "Send an event with a 600-character payload", "Request is rejected or the payload is cut to 500 characters", "auto"),
        ("NFT-S09", "Open the dashboard and /admin/ without logging in", "User is redirected to the login page", "auto"),
        ("NFT-S10", "Enter a wrong password 5 times on the login page", "Account is locked for 1 hour", "auto"),
        ("NFT-S11", "Open the site using http://", "Site redirects to HTTPS and the certificate is valid", "auto"),
        ("NFT-S12", "Export a CSV that contains a payload starting with \"=\"", "Formula characters are neutralised in the CSV", "auto"),
    ]),
    ("3. Non-Functional: Usability Testing (NFT-U + SUS)", [
        ("NFT-U01", "A new user logs in with the account provided, without help", "Login completed within 1 minute", "manual"),
        ("NFT-U02", "Find the top attacker on the dashboard", "Found within 30 seconds", "manual"),
        ("NFT-U03", "Find the country of an attacker on the threat map", "Found within 1 minute", "manual"),
        ("NFT-U04", "Export a PDF report", "Completed within 1 minute without help", "manual"),
        ("NFT-U05", "Find which IPs are currently banned", "Found within 1 minute", "manual"),
    ]),
    ("4. Non-Functional: Reliability Testing (NFT-R)", [
        ("NFT-R01", "Restart the web container", "Stored attack data is still there and the site comes back", "auto"),
        ("NFT-R02", "Run docker compose down, then up", "Stored attack data is still there (database volume persists)", "auto"),
        ("NFT-R03", "Make the server unreachable for a short time while the sensor is running", "Sensor keeps running and sends events when the server returns", "auto"),
        ("NFT-R04", "Re-send the same event after a failed attempt", "No duplicate record is created", "auto"),
        ("NFT-R05", "Ban an IP and wait 10 minutes", "Ban is released automatically", "auto"),
        ("NFT-R06", "Run the system continuously for 24 hours", "No crash or manual restart needed", "soak"),
        ("NFT-R07", "Use the console for 30 minutes (browse, export, refresh)", "No HTTP 500 errors appear", "soak"),
        ("NFT-R08", "Run docker restart honeypot_sensor", "Sensor starts again and captures new attacks from a clean state", "auto"),
        ("NFT-R09", "Check the HTTPS certificate and site reachability", "Certificate is valid and the site stays reachable", "auto"),
    ]),
    ("5. Functional: Unit Testing (FT-U)", [
        ("FT-U01", "Validate attack_type with each of the 7 valid types and one invalid type", "Only the 7 valid types are accepted", "auto"),
        ("FT-U02", "Validate IP addresses (valid and invalid formats)", "Invalid IPs are rejected", "auto"),
        ("FT-U03", "Validate ports -1, 0, 65535 and 65536", "Only 0-65535 is accepted", "auto"),
        ("FT-U04", "Validate sensor IDs esp32-lan, vps-sensor and an unknown ID", "Only the two whitelisted IDs are accepted", "auto"),
        ("FT-U05", "Validate payloads of 500 and 501 characters", "Payload over 500 characters is rejected or cut", "auto"),
        ("FT-U06", "Check the API key with the correct and a wrong key", "Correct key is accepted; wrong key is rejected", "auto"),
        ("FT-U07", "Save two events with the same event_id", "Only one record is stored", "auto"),
        ("FT-U08", "Simulate probes on 3 distinct ports within 5 seconds", "Port scan rule triggers and the IP is banned", "auto"),
        ("FT-U09", "Simulate 3 failed logins within 60 seconds", "Brute force rule triggers and the IP is banned", "auto"),
        ("FT-U10", "Check a ban after 10 minutes", "Ban has expired", "auto"),
        ("FT-U11", "Run the CSV exporter on a payload starting with = + - or @", "Formula characters are sanitised", "auto"),
        ("FT-U12", "Run the PDF report builder with sample data", "A valid PDF file is returned", "auto"),
        ("FT-U13", "Run the full automated test suite", "All 52 tests pass", "auto"),
    ]),
    ("6. Functional: Integration Testing (FT-I)", [
        ("FT-I01", "Sensor sends an event to the ingest API", "API returns success", "auto"),
        ("FT-I02", "Check the database after an event is ingested", "Event is saved in the attacklog table", "auto"),
        ("FT-I03", "Ingest an event from a public IP", "GeoIP adds country and city to the attackergeo record", "auto"),
        ("FT-I04", "Ingest a new event and open the dashboard", "Stat bar totals are updated", "auto"),
        ("FT-I05", "Ingest a new event and open the threat map", "Attacker appears as a marker in the correct country", "auto"),
        ("FT-I06", "Open an attacker profile after several events", "Hourly chart matches the stored events", "auto"),
        ("FT-I07", "Export CSV and PDF reports", "Reports contain the same data as the attack log", "auto"),
        ("FT-I08", "Start the stack with docker compose up", "web, db and nginx containers communicate without errors", "auto"),
        ("FT-I09", "Open the site through host nginx with Let's Encrypt", "Console loads over HTTPS", "auto"),
        ("FT-I10", "Send events from both sensors (esp32-lan and vps-sensor)", "Both appear in the same console with the correct sensor ID", "auto"),
    ]),
    ("7. Functional: System Testing (FT-S)", [
        ("FT-S01", "Run docker compose up", "All 4 services start with one command", "auto"),
        ("FT-S02", "Log in as admin and open the dashboard", "Dashboard opens with all panels visible", "auto"),
        ("FT-S03", "Connect to the fake telnet service and enter a username and password", "Credentials are captured in the attack payload", "auto"),
        ("FT-S04", "Scan 3 ports on the sensor within 5 seconds", "Logged as port_scan and the IP is banned", "auto"),
        ("FT-S05", "Probe the sensor again while banned", "Logged as ip_blocked (throttled to once per 30 seconds)", "auto"),
        ("FT-S06", "Send an HTTP request to the sensor and open a fake admin page", "Logged as http_scan or admin_panel_access", "auto"),
        ("FT-S07", "Generate all 7 attack types", "All 7 types appear in the attack log", "auto"),
        ("FT-S08", "Trigger an attack and watch the dashboard", "New attack appears within 10 seconds", "auto"),
        ("FT-S09", "Export CSV and PDF reports", "Both files download and open correctly", "auto"),
        ("FT-S10", "Restart the whole stack", "All data is still there", "auto"),
    ]),
    ("8. User Acceptance Testing (UAT)", [
        ("UAT-01", "Log in with the account provided", "Login succeeds and the dashboard opens", "manual"),
        ("UAT-02", "View the dashboard", "Total attacks, top attacker and attack types are clear", "manual"),
        ("UAT-03", "Watch the dashboard for 30 seconds", "New attacks appear automatically and the alert badge is noticeable", "manual"),
        ("UAT-04", "Open the threat map", "Map clearly shows where attackers come from", "manual"),
        ("UAT-05", "Open an attacker profile", "IP, country and activity are easy to understand", "manual"),
        ("UAT-06", "Open the attack log", "Individual attack records are easy to find and read", "manual"),
        ("UAT-07", "Export a CSV report", "CSV file downloads and opens correctly", "manual"),
        ("UAT-08", "Export a PDF report", "PDF looks professional and is usable as evidence", "manual"),
        ("UAT-09", "Check the banned IPs", "It is clear which attackers were blocked and why", "manual"),
    ]),
]

# System Usability Scale statements (Section 3b) — participants rate 1..5;
# score_forms.py computes the 0-100 score from collected responses.
SUS_STATEMENTS = [
    "I think I would like to use this system frequently.",
    "I found the system unnecessarily complex.",
    "I thought the system was easy to use.",
    "I think I would need technical support to use this system.",
    "I found the various functions in this system well integrated.",
    "I thought there was too much inconsistency in this system.",
    "I imagine most people would learn to use this system very quickly.",
    "I found the system very cumbersome to use.",
    "I felt very confident using the system.",
    "I needed to learn a lot of things before I could get going with this system.",
]

# UAT overall acceptance statements (1 = Strongly disagree .. 5 = Strongly agree)
UAT_STATEMENTS = [
    "The system does what a small business needs for attack monitoring.",
    "The system is easy to learn without training.",
    "The information shown is accurate and useful.",
    "The system is reliable (no errors or crashes while I used it).",
    "The system is suitable for a small business like Yumplingy.",
    "I would recommend this system to others.",
]

ALL_IDS = [tid for _, rows in SECTIONS for tid, _, _, _ in rows]
BY_ID = {tid: (sec, desc, exp, mode) for sec, rows in SECTIONS for tid, desc, exp, mode in rows}