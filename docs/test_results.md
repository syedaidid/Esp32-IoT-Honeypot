# Automated Test Results — FYP4112 ESP32 IoT Honeypot

**Generated:** 2026-10-06 03:32 (automated harness `scripts/autotest/`)  
**Total test cases:** 77 (61 automated/executed · 14 human-only · 2 not yet run)  
**Automated results:** 60 pass · 1 not pass (1 fail · 0 blocked · 0 skip)  
**Automated pass rate:** 98.4% (60/61 executed cases)  
> Human-only cases (usability questionnaire + UAT) are not machine-scored; score them with `score_forms.py` once responses are collected.

## 1. Non-Functional: Performance Testing (NFT-P)

| Test ID | Test Description | Expected Result | Actual Result | Status |
|---|---|---|---|---|
| NFT-P01 | Load the SOC dashboard (stat bar, 24-hour chart, threat doughnut) under normal conditions | Page loads within 5 seconds | status=200; render=0.14s (limit 5s); panels={'stat bar': True, 'chart': True, 'map': True, 'table': True} | PASS |
| NFT-P02 | Load the threat map page with attacker markers | Page loads within 5 seconds | status=200; render=0.02s (limit 5s) | PASS |
| NFT-P03 | Leave the dashboard open for 30 seconds and observe the 10-second auto-refresh | Data refreshes about every 10 seconds without a page reload or freeze | JS 10s interval present=True; /api/latest/ -> 200 | PASS |
| NFT-P04 | Open the attack log when it holds 1,000+ events | Page responds within 5 seconds | 1114 events in log; render=0.09s (limit 5s) | PASS |
| NFT-P05 | Export the PDF forensic report | Report is generated within 10 seconds | PDF in 0.14s (limit 10s); 13443 bytes | PASS |
| NFT-P06 | Export the CSV report | File is generated within 5 seconds | CSV in 0.03s (limit 5s); 23133 bytes | PASS |
| NFT-P07 | Send 60 valid requests in one minute to /api/attacks/ from one IP | All 60 requests are accepted (HTTP 2xx) | 60 requests -> 60 accepted (expect 60) | PASS |
| NFT-P08 | Send a 61st request within the same minute | Request is rejected with HTTP 429 | 61st request -> 429 (expect 429) | PASS |
| NFT-P09 | Probe 3 different ports on the sensor within 5 seconds | Detected as port_scan and the IP is banned within 5 seconds | 3 ports -> events=['port_scan', 'ip_blocked']; banned=True; probe while banned added 0 extra events (throttled) | PASS |

## 2. Non-Functional: Security Testing (NFT-S)

| Test ID | Test Description | Expected Result | Actual Result | Status |
|---|---|---|---|---|
| NFT-S01 | Send POST /api/attacks/ without an X-API-Key header | Request is rejected (HTTP 401/403) and nothing is stored | no key -> 403; new rows=0 | PASS |
| NFT-S02 | Send POST /api/attacks/ with a wrong API key | Request is rejected and nothing is stored | wrong key -> 403; new rows=0 | PASS |
| NFT-S03 | Send more than 60 requests in one minute from one IP | Extra requests are rejected with HTTP 429 | 61st request -> 429 (expect 429) | PASS |
| NFT-S04 | Send the same event_id twice | Second request is ignored; only one record is stored | duplicate event_id -> rows=1 (expect 1) | PASS |
| NFT-S05 | Send an event with an invalid IP (e.g. 999.1.1.1) | Request is rejected with a validation error | invalid IP -> 400 (expect 400) | PASS |
| NFT-S06 | Send an event with port 70000 | Request is rejected with a validation error | port 70000 -> 400 (expect 400) | PASS |
| NFT-S07 | Send an event with sensor ID "fake-sensor" | Request is rejected (not in the sensor whitelist) | fake-sensor -> 400 (expect 400) | PASS |
| NFT-S08 | Send an event with a 600-character payload | Request is rejected or the payload is cut to 500 characters | 600-char payload stored as len=500 (cut to 500) | PASS |
| NFT-S09 | Open the dashboard and /admin/ without logging in | User is redirected to the login page | unauth / -> 302, /admin/ -> 302 (expect redirect) | PASS |
| NFT-S10 | Enter a wrong password 5 times on the login page | Account is locked for 1 hour | 5 wrong then correct -> 429 (403/429 = locked) | PASS |
| NFT-S11 | Open the site using http:// | Site redirects to HTTPS and the certificate is valid | http -> 301 Location=https://fyp.syedaidid.xyz/; cert issuer=Let's Encrypt, valid until Dec 31 19:54:15 2026 GMT | PASS |
| NFT-S12 | Export a CSV that contains a payload starting with "=" | Formula characters are neutralised in the CSV | 4 formula payloads stored+exported; un-neutralised cells: none | PASS |

## 3. Non-Functional: Usability Testing (NFT-U + SUS)

| Test ID | Test Description | Expected Result | Actual Result | Status |
|---|---|---|---|---|
| NFT-U01 | A new user logs in with the account provided, without help | Login completed within 1 minute | — | MANUAL |
| NFT-U02 | Find the top attacker on the dashboard | Found within 30 seconds | — | MANUAL |
| NFT-U03 | Find the country of an attacker on the threat map | Found within 1 minute | — | MANUAL |
| NFT-U04 | Export a PDF report | Completed within 1 minute without help | — | MANUAL |
| NFT-U05 | Find which IPs are currently banned | Found within 1 minute | — | MANUAL |

### 3b. System Usability Scale (1 = Strongly disagree, 5 = Strongly agree)

| # | Statement | Rating (1-5) |
|---|---|---|
| 1 | I think I would like to use this system frequently. | |
| 2 | I found the system unnecessarily complex. | |
| 3 | I thought the system was easy to use. | |
| 4 | I think I would need technical support to use this system. | |
| 5 | I found the various functions in this system well integrated. | |
| 6 | I thought there was too much inconsistency in this system. | |
| 7 | I imagine most people would learn to use this system very quickly. | |
| 8 | I found the system very cumbersome to use. | |
| 9 | I felt very confident using the system. | |
| 10 | I needed to learn a lot of things before I could get going with this system. | |

SUS scoring: odd statements (rating − 1); even statements (5 − rating); sum × 2.5. Automated scoring: `python scripts/autotest/score_forms.py`.

## 4. Non-Functional: Reliability Testing (NFT-R)

| Test ID | Test Description | Expected Result | Actual Result | Status |
|---|---|---|---|---|
| NFT-R01 | Restart the web container | Stored attack data is still there and the site comes back | count 4078 -> 4078; site reachable in 2.1s | PASS |
| NFT-R02 | Run docker compose down, then up | Stored attack data is still there (database volume persists) | count 4079 -> 4079; site reachable in 2.1s | PASS |
| NFT-R03 | Make the server unreachable for a short time while the sensor is running | Sensor keeps running and sends events when the server returns | dead-endpoint POST handled without exception; console reports :23 -> 0 | PASS |
| NFT-R04 | Re-send the same event after a failed attempt | No duplicate record is created | retry with same event_id -> rows=1 (expect 1) | PASS |
| NFT-R05 | Ban an IP and wait 10 minutes | Ban is released automatically | banned=True before 10min; after +601s banned=False | PASS |
| NFT-R06 | Run the system continuously for 24 hours | No crash or manual restart needed | — | NOT RUN |
| NFT-R07 | Use the console for 30 minutes (browse, export, refresh) | No HTTP 500 errors appear | — | NOT RUN |
| NFT-R08 | Run docker restart honeypot_sensor | Sensor starts again and captures new attacks from a clean state | sensor restarted and captured a fresh probe (clean state) | PASS |
| NFT-R09 | Check the HTTPS certificate and site reachability | Certificate is valid and the site stays reachable | 3/3 probes returned 200; cert valid=True | PASS |

## 5. Functional: Unit Testing (FT-U)

| Test ID | Test Description | Expected Result | Actual Result | Status |
|---|---|---|---|---|
| FT-U01 | Validate attack_type with each of the 7 valid types and one invalid type | Only the 7 valid types are accepted | 7 valid types -> [201, 201, 201, 201, 201, 201, 201]; invalid -> 400 (expect 400) | PASS |
| FT-U02 | Validate IP addresses (valid and invalid formats) | Invalid IPs are rejected | valid -> [201, 201, 201]; invalid -> [400, 400, 400] (expect 400s) | PASS |
| FT-U03 | Validate ports -1, 0, 65535 and 65536 | Only 0-65535 is accepted | 0/65535 -> [201, 201]; -1/65536 -> [400, 400] (expect 400s) | PASS |
| FT-U04 | Validate sensor IDs esp32-lan, vps-sensor and an unknown ID | Only the two whitelisted IDs are accepted | whitelist -> [201, 201]; fake-sensor -> 400 (expect 400) | PASS |
| FT-U05 | Validate payloads of 500 and 501 characters | Payload over 500 characters is rejected or cut | 501-char payload stored as len=500 (cut to 500) | PASS |
| FT-U06 | Check the API key with the correct and a wrong key | Correct key is accepted; wrong key is rejected | correct key -> 201; wrong key -> 403 (expect 403) | PASS |
| FT-U07 | Save two events with the same event_id | Only one record is stored | same event_id twice -> rows=1 (expect 1); second status=200 | PASS |
| FT-U08 | Simulate probes on 3 distinct ports within 5 seconds | Port scan rule triggers and the IP is banned | 3 ports in 5s -> events=['port_scan', 'ip_blocked']; banned=True | PASS |
| FT-U09 | Simulate 3 failed logins within 60 seconds | Brute force rule triggers and the IP is banned | 3 fails in 60s -> events=['brute_force', 'ip_blocked']; banned=True | PASS |
| FT-U10 | Check a ban after 10 minutes | Ban has expired | banned=True before 10min; after +601s banned=False | PASS |
| FT-U11 | Run the CSV exporter on a payload starting with = + - or @ | Formula characters are sanitised | 4 formula payloads stored+exported; un-neutralised cells: none | PASS |
| FT-U12 | Run the PDF report builder with sample data | A valid PDF file is returned | status=200; magic=b'%PDF'; 13429 bytes | PASS |
| FT-U13 | Run the full automated test suite | All 52 tests pass | 52/52 unit tests OK in the deployed environment [honeypot.settings_local] — Ran 52 tests in 56.497s | PASS |

## 6. Functional: Integration Testing (FT-I)

| Test ID | Test Description | Expected Result | Actual Result | Status |
|---|---|---|---|---|
| FT-I01 | Sensor sends an event to the ingest API | API returns success | POST -> 201; row in DB id=12480 | PASS |
| FT-I02 | Check the database after an event is ingested | Event is saved in the attacklog table | POST -> 201; row in DB id=12481 | PASS |
| FT-I03 | Ingest an event from a public IP | GeoIP adds country and city to the attackergeo record | geo for 8.8.8.8: country=United States city=Ashburn | PASS |
| FT-I04 | Ingest a new event and open the dashboard | Stat bar totals are updated | dashboard total 110 -> 111 | PASS |
| FT-I05 | Ingest a new event and open the threat map | Attacker appears as a marker in the correct country | map context rows=2, IP present=True; /api/geo/ origins=2 (top-200 window), IP present with count=3/3 | PASS |
| FT-I06 | Open an attacker profile after several events | Hourly chart matches the stored events | profile total=4, 24h chart sum=4, DB rows=4 | PASS |
| FT-I07 | Export CSV and PDF reports | Reports contain the same data as the attack log | DB rows=111; CSV data rows=111; PDF magic=b'%PDF' | PASS |
| FT-I08 | Start the stack with docker compose up | web, db and nginx containers communicate without errors | 4 services running: honeypot_db honeypot_nginx honeypot_sensor honeypot_web | PASS |
| FT-I09 | Open the site through host nginx with Let's Encrypt | Console loads over HTTPS | login page 200 (form=True, 1.15s); unauth / -> 302 /accounts/login/?next=/ | PASS |
| FT-I10 | Send events from both sensors (esp32-lan and vps-sensor) | Both appear in the same console with the correct sensor ID | latest feed sensors for test rows: {'vps-sensor', 'esp32-lan'} | PASS |

## 7. Functional: System Testing (FT-S)

| Test ID | Test Description | Expected Result | Actual Result | Status |
|---|---|---|---|---|
| FT-S01 | Run docker compose up | All 4 services start with one command | 4 services running: honeypot_db honeypot_nginx honeypot_sensor honeypot_web | PASS |
| FT-S02 | Log in as admin and open the dashboard | Dashboard opens with all panels visible | login POST -> 302 /; dashboard 200; all panels visible=True | PASS |
| FT-S03 | Connect to the fake telnet service and enter a username and password | Credentials are captured in the attack payload | credentials captured: payload contains user='autotest_user' + password | PASS |
| FT-S04 | Scan 3 ports on the sensor within 5 seconds | Logged as port_scan and the IP is banned | scanned [2323, 21, 5555] in 0.0s -> port_scan logged (127.0.0.1 now banned) | PASS |
| FT-S05 | Probe the sensor again while banned | Logged as ip_blocked (throttled to once per 30 seconds) | ip_blocked rows 4 -> 5 after 3 rapid probes while banned (throttle = max 1 per 30s) | PASS |
| FT-S06 | Send an HTTP request to the sensor and open a fake admin page | Logged as http_scan or admin_panel_access | no HTTP decoy service — the VPS sensor exposes telnet/FTP/ADB/TR-069 traps only, so http_scan/admin_panel_access are recorded only via ingest (ESP32 firmware has the HTTP decoy; untested, no hardware) | FAIL |
| FT-S07 | Generate all 7 attack types | All 7 types appear in the attack log | types in log for test IP: ['admin_panel_access', 'brute_force', 'connection_attempt', 'http_brute_force', 'http_scan', 'ip_blocked', 'port_scan'] | PASS |
| FT-S08 | Trigger an attack and watch the dashboard | New attack appears within 10 seconds | ingested id=12500; newest in live feed id=12500 | PASS |
| FT-S09 | Export CSV and PDF reports | Both files download and open correctly | CSV 115 rows parse OK; PDF magic=b'%PDF' | PASS |
| FT-S10 | Restart the whole stack | All data is still there | count 4079 -> 4079; site reachable in 2.0s | PASS |

## 8. User Acceptance Testing (UAT)

| Test ID | Test Description | Expected Result | Actual Result | Status |
|---|---|---|---|---|
| UAT-01 | Log in with the account provided | Login succeeds and the dashboard opens | — | MANUAL |
| UAT-02 | View the dashboard | Total attacks, top attacker and attack types are clear | — | MANUAL |
| UAT-03 | Watch the dashboard for 30 seconds | New attacks appear automatically and the alert badge is noticeable | — | MANUAL |
| UAT-04 | Open the threat map | Map clearly shows where attackers come from | — | MANUAL |
| UAT-05 | Open an attacker profile | IP, country and activity are easy to understand | — | MANUAL |
| UAT-06 | Open the attack log | Individual attack records are easy to find and read | — | MANUAL |
| UAT-07 | Export a CSV report | CSV file downloads and opens correctly | — | MANUAL |
| UAT-08 | Export a PDF report | PDF looks professional and is usable as evidence | — | MANUAL |
| UAT-09 | Check the banned IPs | It is clear which attackers were blocked and why | — | MANUAL |

### Overall acceptance (1 = Strongly disagree, 5 = Strongly agree)

| # | Statement | Rating (1-5) |
|---|---|---|
| 1 | The system does what a small business needs for attack monitoring. | |
| 2 | The system is easy to learn without training. | |
| 3 | The information shown is accurate and useful. | |
| 4 | The system is reliable (no errors or crashes while I used it). | |
| 5 | The system is suitable for a small business like Yumplingy. | |
| 6 | I would recommend this system to others. | |

**Final decision:** Accept / Accept with minor changes / Reject

**Open feedback:** What did you like most? What problems did you face? What would you improve?
