from django.db import models

class AttackLog(models.Model):
    attacker_ip = models.CharField(max_length=50)
    port = models.IntegerField()
    attack_type = models.CharField(max_length=50)
    payload = models.TextField(blank=True, null=True)
    # Client-generated event id — unique so retries / duplicate POSTs are idempotent.
    # NULL allowed for legacy rows created before this field existed.
    event_id = models.CharField(max_length=64, unique=True, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.attack_type} from {self.attacker_ip} on port {self.port}"
