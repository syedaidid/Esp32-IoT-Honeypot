"""
System/unit tests for the ESP32 IoT honeypot backend.

Covers functionality (U22-U46):
  U22-U30  /api/attacks/ ingest: valid events, validation, idempotency
  NEW      API-key auth (403 without/with wrong key) and rate limiting (429)
  U31-U32  /api/latest/ and /api/stats/ (auth + shape)
  U33      dashboard
  U34-U37  /logs/ search, filters, pagination
  U38-U39  /attackers/ aggregation and attacker detail
  U40-U41  CSV + PDF report export
  U42-U46  login, failed login, axes lockout, logout, session guard

Run:  python3 manage.py test detector --settings=honeypot.settings_local
"""

import json
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from django.urls import reverse
from django.core.cache import cache

from .models import AttackLog

VALID_IP = "192.0.2.10"        # TEST-NET-1, never routed publicly
EVENT = {
    "attacker_ip": VALID_IP,
    "port": 8080,
    "attack_type": "port_scan",
    "payload": "nmap -sS -p 1-10000",
}


@override_settings(HONEYPOT_API_KEY="test-key")
class IngestEndpointTests(TestCase):
    """U22-U30 + API-key auth + dedup + rate limit."""

    def setUp(self):
        self.valid_key = {"HTTP_X_API_KEY": "test-key"}
        self.ingest_url = reverse("receive_attack")
        cache.clear()

    def post_event(self, data=EVENT, key=True, as_json=True):
        """POST an event to /api/attacks/ with the shared API key by default."""
        headers = self.valid_key if key else {}
        return self.client.post(
            self.ingest_url,
            data=json.dumps(data) if as_json else data,
            content_type="application/json" if as_json else "text/plain",
            **headers,
        )

    # ── U22: valid event is stored ──
    def test_valid_event_returns_201_and_creates_row(self):
        resp = self.post_event()
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.json()["status"], "ok")
        row = AttackLog.objects.get()
        self.assertEqual(row.attacker_ip, VALID_IP)
        self.assertEqual(row.port, 8080)
        self.assertEqual(row.attack_type, "port_scan")

    # ── NEW: API key auth ──
    def test_missing_api_key_rejected_403(self):
        resp = self.post_event(key=False)
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(AttackLog.objects.count(), 0)

    def test_wrong_api_key_rejected_403(self):
        resp = self.client.post(
            self.ingest_url, data=json.dumps(EVENT),
            content_type="application/json", HTTP_X_API_KEY="wrong-key")
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(AttackLog.objects.count(), 0)

    # ── U23: invalid IP ──
    def test_invalid_ip_rejected_400(self):
        resp = self.post_event({**EVENT, "attacker_ip": "not-an-ip"})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(AttackLog.objects.count(), 0)

    def test_empty_ip_rejected_400(self):
        resp = self.post_event({**EVENT, "attacker_ip": ""})
        self.assertEqual(resp.status_code, 400)

    # ── U24: invalid port ──
    def test_negative_port_rejected_400(self):
        resp = self.post_event({**EVENT, "port": -1})
        self.assertEqual(resp.status_code, 400)

    def test_non_numeric_port_rejected_400(self):
        resp = self.post_event({**EVENT, "port": "8080"})
        self.assertEqual(resp.status_code, 400)

    # ── U25: unknown attack_type ──
    def test_unknown_attack_type_rejected_400(self):
        resp = self.post_event({**EVENT, "attack_type": "ddos_amplification"})
        self.assertEqual(resp.status_code, 400)

    # ── U30: every known attack_type is accepted ──
    def test_all_known_attack_types_accepted(self):
        for i, atype in enumerate([
                "port_scan", "brute_force", "connection_attempt",
                "http_scan", "http_brute_force", "admin_panel_access",
                "ip_blocked"]):
            resp = self.post_event({
                **EVENT, "attack_type": atype,
                "port": 1000 + i, "attacker_ip": f"192.0.2.{i + 1}"})
            self.assertEqual(resp.status_code, 201, msg=atype)
        self.assertEqual(AttackLog.objects.count(), 7)

    # ── U26: payload truncated to 500 chars ──
    def test_payload_truncated_to_500(self):
        long_payload = "A" * 600
        resp = self.post_event({**EVENT, "payload": long_payload})
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(len(AttackLog.objects.get().payload), 500)

    # ── U27: non-string payload coerced ──
    def test_non_string_payload_coerced(self):
        resp = self.post_event({**EVENT, "payload": 12345})
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(AttackLog.objects.get().payload, "12345")

    # ── U28: malformed JSON ──
    def test_malformed_json_rejected_400(self):
        resp = self.client.post(self.ingest_url, data="{bad json",
                                content_type="application/json",
                                **self.valid_key)
        self.assertEqual(resp.status_code, 400)

    def test_wrong_method_rejected_405(self):
        resp = self.client.get(self.ingest_url, **self.valid_key)
        self.assertEqual(resp.status_code, 405)

    # ── NEW: idempotent event_id dedup ──
    def test_duplicate_event_id_is_idempotent(self):
        first = self.post_event({**EVENT, "event_id": "evt-001"})
        second = self.post_event({**EVENT, "event_id": "evt-001"})
        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.json()["status"], "duplicate")
        self.assertEqual(second.json()["id"], first.json()["id"])
        self.assertEqual(AttackLog.objects.count(), 1)

    def test_missing_event_id_still_logged(self):
        resp = self.post_event({**EVENT})
        self.assertEqual(resp.status_code, 201)
        self.assertIsNone(AttackLog.objects.get().event_id)

    def test_overlong_event_id_truncated(self):
        resp = self.post_event({**EVENT, "event_id": "x" * 100})
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(len(AttackLog.objects.get().event_id), 64)

    # ── NEW: per-IP rate limit ──
    @mock.patch("detector.views.INGEST_RATE_LIMIT", 3)
    def test_rate_limit_returns_429_after_limit(self):
        cache.clear()
        for _ in range(3):
            self.assertEqual(self.post_event().status_code, 201)
        resp = self.post_event()
        self.assertEqual(resp.status_code, 429)


@override_settings(HONEYPOT_API_KEY="test-key")
class AuthenticatedApiTests(TestCase):
    """U31-U32: /api/latest/ and /api/stats/."""

    def setUp(self):
        self.user = User.objects.create_user(username="ops", password="pass")
        self.headers = {"HTTP_X_API_KEY": "test-key"}
        self.ingest_url = reverse("receive_attack")

    def seed(self, n, ip="198.51.100.7"):
        for i in range(n):
            AttackLog.objects.create(
                attacker_ip=ip, port=22, attack_type="brute_force",
                payload=f"attempt {i}")

    # ── U31: latest is login-protected and caps at 10, newest first ──
    def test_latest_requires_login(self):
        resp = self.client.get(reverse("latest_attacks"))
        self.assertEqual(resp.status_code, 302)

    def test_latest_returns_ten_newest(self):
        self.seed(12)
        self.client.force_login(self.user)
        resp = self.client.get(reverse("latest_attacks"))
        self.assertEqual(resp.status_code, 200)
        attacks = resp.json()["attacks"]
        self.assertEqual(len(attacks), 10)
        self.assertEqual(attacks[0]["payload"], "attempt 11")  # newest first

    # ── U32: stats shape ──
    def test_stats_requires_login(self):
        resp = self.client.get(reverse("stats_api"))
        self.assertEqual(resp.status_code, 302)

    def test_stats_shape_and_counts(self):
        self.seed(5)
        AttackLog.objects.create(attacker_ip="203.0.113.9", port=80,
                                 attack_type="http_scan", payload="GET /admin")
        self.client.force_login(self.user)
        resp = self.client.get(reverse("stats_api"))
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["total"], 6)
        self.assertEqual(body["unique_ips"], 2)
        self.assertIn("by_type", body)
        self.assertIn("by_port", body)
        self.assertIn("banned", body)


class DashboardTests(TestCase):
    """U33: dashboard metrics."""

    def setUp(self):
        self.user = User.objects.create_user(username="ops", password="pass")

    def test_dashboard_requires_login(self):
        resp = self.client.get(reverse("dashboard"))
        self.assertEqual(resp.status_code, 302)

    def test_dashboard_context_metrics(self):
        AttackLog.objects.create(attacker_ip="198.51.100.1", port=22,
                                 attack_type="brute_force")
        AttackLog.objects.create(attacker_ip="198.51.100.2", port=22,
                                 attack_type="ip_blocked")
        self.client.force_login(self.user)
        resp = self.client.get(reverse("dashboard"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context["total"], 2)
        self.assertEqual(resp.context["unique_ips"], 2)


class LogsTests(TestCase):
    """U34-U37: search, filters, pagination on /logs/."""

    def setUp(self):
        self.user = User.objects.create_user(username="ops", password="pass")
        self.client.force_login(self.user)
        self.urls_base = {"q": "1.1.1.1", "type": "port_scan", "port": "8080"}

        AttackLog.objects.create(attacker_ip="1.1.1.1", port=8080,
                                 attack_type="port_scan", payload="nmap -sS")
        AttackLog.objects.create(attacker_ip="2.2.2.2", port=22,
                                 attack_type="brute_force", payload="hydra")
        AttackLog.objects.create(attacker_ip="10.0.0.55", port=443,
                                 attack_type="http_scan", payload="dirbuster")

    def test_logs_require_login(self):
        self.client.logout()
        resp = self.client.get(reverse("attack_logs"))
        self.assertEqual(resp.status_code, 302)

    # ── U34: keyword search hits IP or payload ──
    def test_search_by_ip(self):
        resp = self.client.get(reverse("attack_logs"), {"q": "2.2.2.2"})
        ips = [l.attacker_ip for l in resp.context["page"].object_list]
        self.assertEqual(ips, ["2.2.2.2"])

    def test_search_by_payload(self):
        resp = self.client.get(reverse("attack_logs"), {"q": "dirbuster"})
        self.assertEqual(len(resp.context["page"].object_list), 1)

    # ── U35: type filter ──
    def test_filter_by_type(self):
        resp = self.client.get(reverse("attack_logs"), {"type": "brute_force"})
        rows = resp.context["page"].object_list
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].attack_type, "brute_force")

    # ── U36: port + date range filters ──
    def test_filter_by_port(self):
        resp = self.client.get(reverse("attack_logs"), {"port": "443"})
        rows = resp.context["page"].object_list
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].port, 443)

    def test_invalid_port_filter_is_silent(self):
        resp = self.client.get(reverse("attack_logs"), {"port": "abc"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.context["page"].object_list), 3)

    def test_date_range_filter(self):
        # backdate one row to yesterday
        from django.utils import timezone
        from datetime import timedelta
        old = AttackLog.objects.get(attacker_ip="10.0.0.55")
        AttackLog.objects.filter(pk=old.pk).update(
            timestamp=timezone.now() - timedelta(days=2))
        resp = self.client.get(reverse("attack_logs"), {"from": (timezone.localdate(
            ) + timedelta(days=-1)).isoformat()})
        self.assertEqual(len(resp.context["page"].object_list), 2)

    # ── U37: pagination (25/page) ──
    def test_pagination_page_size(self):
        for i in range(30):
            AttackLog.objects.create(attacker_ip=f"203.0.113.{i % 250}", port=80,
                                     attack_type="http_scan")
        resp = self.client.get(reverse("attack_logs"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.context["page"].object_list), 25)
        resp2 = self.client.get(reverse("attack_logs"), {"page": 2})
        self.assertEqual(resp2.status_code, 200)


class AttackersTests(TestCase):
    """U38-U39: aggregation + forensic profile."""

    def setUp(self):
        self.user = User.objects.create_user(username="ops", password="pass")
        self.client.force_login(self.user)

    def test_attackers_aggregation_ordered_by_count(self):
        for _ in range(5):
            AttackLog.objects.create(attacker_ip="1.1.1.1", port=22,
                                     attack_type="brute_force")
        AttackLog.objects.create(attacker_ip="2.2.2.2", port=80,
                                 attack_type="http_scan")
        resp = self.client.get(reverse("attackers"))
        rows = resp.context["page"].object_list
        self.assertEqual(rows[0]["attacker_ip"], "1.1.1.1")
        self.assertEqual(rows[0]["total"], 5)
        self.assertEqual(rows[1]["total"], 1)

    def test_attacker_detail_profile(self):
        for i in range(3):
            AttackLog.objects.create(attacker_ip="198.51.100.42", port=22,
                                     attack_type="brute_force")
        AttackLog.objects.create(attacker_ip="198.51.100.42", port=80,
                                 attack_type="ip_blocked")
        resp = self.client.get(reverse("attacker_detail", args=["198.51.100.42"]))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context["total"], 4)
        self.assertEqual(resp.context["blocked_hits"], 1)
        self.assertEqual(sum(resp.context["hourly"]), 4)  # all within 24h

    def test_attacker_detail_unknown_ip_empty(self):
        resp = self.client.get(reverse("attacker_detail", args=["203.0.113.9"]))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context["total"], 0)


class ExportTests(TestCase):
    """U40-U41: CSV + PDF exports."""

    def setUp(self):
        self.user = User.objects.create_user(username="ops", password="pass")
        self.client.force_login(self.user)
        AttackLog.objects.create(attacker_ip="198.51.100.7", port=22,
                                 attack_type="brute_force",
                                 payload="line1\nline2, with comma")

    def test_csv_export_header_and_rows(self):
        resp = self.client.get(reverse("export_csv"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "text/csv")
        lines = resp.content.decode().splitlines()
        self.assertEqual(lines[0], "id,attacker_ip,port,attack_type,payload,timestamp")
        self.assertEqual(len(lines), 2)  # header + one row
        self.assertIn("198.51.100.7", lines[1])
        self.assertNotIn("\n", lines[1])  # newlines sanitised

    def test_csv_requires_login(self):
        self.client.logout()
        resp = self.client.get(reverse("export_csv"))
        self.assertEqual(resp.status_code, 302)

    def test_forensic_report_pdf(self):
        resp = self.client.get(reverse("forensic_report"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "application/pdf")
        self.assertIn(b"%PDF", resp.content[:5])


class AuthTests(TestCase):
    """U42-U46: login, failed login, lockout, logout, session guard."""

    def setUp(self):
        self.user = User.objects.create_user(
            username="admin", password="correct-password")
        cache.clear()

    def test_login_success_redirects(self):
        resp = self.client.post(reverse("login"),
                                {"username": "admin",
                                 "password": "correct-password"})
        self.assertEqual(resp.status_code, 302)

    def test_login_failure_shows_error(self):
        resp = self.client.post(reverse("login"),
                                {"username": "admin", "password": "wrong"})
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "errors")

    @override_settings(AXES_FAILURE_LIMIT=3)
    def test_account_locked_out_after_three_failures(self):
        for _ in range(3):
            self.client.post(reverse("login"),
                             {"username": "admin", "password": "wrong"})
        # Even correct credentials are rejected once locked (axes 8.x uses 429)
        resp = self.client.post(reverse("login"),
                                {"username": "admin",
                                 "password": "correct-password"})
        self.assertIn(resp.status_code, [403, 429])  # axes returns 429 (or 403 pre-8.x)

    def test_logout_ends_session(self):
        self.client.force_login(self.user)  # force_login bypasses axes authenticate()
        resp = self.client.post(reverse("logout"))  # LogoutView requires POST
        self.assertEqual(resp.status_code, 302)
        resp = self.client.get(reverse("dashboard"))
        self.assertEqual(resp.status_code, 302)  # redirected to login again