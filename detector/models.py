from django.db import models

# Sensors allowed to POST events (validated on ingest).
SENSOR_IDS = {'esp32-lan', 'vps-sensor'}

class AttackLog(models.Model):
    attacker_ip = models.CharField(max_length=50)
    port = models.IntegerField()
    attack_type = models.CharField(max_length=50)
    payload = models.TextField(blank=True, null=True)
    # Client-generated event id — unique so retries / duplicate POSTs are idempotent.
    # NULL allowed for legacy rows created before this field existed.
    event_id = models.CharField(max_length=64, unique=True, null=True, blank=True)
    # Which honeypot sensor observed the event ('esp32-lan' or 'vps-sensor').
    sensor = models.CharField(max_length=20, default='esp32-lan')
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.attack_type} from {self.attacker_ip} on port {self.port} [{self.sensor}]"


class AttackerGeo(models.Model):
    """GeoIP lookup cache — one row per attacker IP (lookups are rate-limited
    against the free ip-api tier, so we never re-query a known IP)."""
    attacker_ip = models.CharField(max_length=50, unique=True)
    country = models.CharField(max_length=80, blank=True, null=True)
    country_code = models.CharField(max_length=2, blank=True, null=True)
    city = models.CharField(max_length=80, blank=True, null=True)
    latitude = models.FloatField(blank=True, null=True)
    longitude = models.FloatField(blank=True, null=True)
    isp = models.CharField(max_length=120, blank=True, null=True)
    lookup_failed = models.BooleanField(default=False)   # true → private/unknown IP, don't retry
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        loc = self.city or self.country or '?'
        return f"{self.attacker_ip} → {loc}"