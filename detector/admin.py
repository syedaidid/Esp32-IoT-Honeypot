from django.contrib import admin
from .models import AttackLog

@admin.register(AttackLog)
class AttackLogAdmin(admin.ModelAdmin):
    list_display = ['id', 'attacker_ip', 'port', 'attack_type', 'payload_preview', 'timestamp']
    list_filter = ['attack_type', 'port']
    search_fields = ['attacker_ip', 'attack_type', 'payload']
    ordering = ['-timestamp']
    readonly_fields = ['attacker_ip', 'port', 'attack_type', 'payload', 'timestamp']
    list_per_page = 25

    def payload_preview(self, obj):
        return obj.payload[:40] + '...' if len(obj.payload) > 40 else obj.payload
    payload_preview.short_description = 'Payload'

# Register your models here.
