"""Terminal severity mapping for the SOC console.

Maps attack_type → terminal severity tier used for row accents and badges:
  sev-crit : ip_blocked          (confirmed repeat offender)
  sev-high : port_scan, brute_force
  sev-med  : http_brute_force, admin_panel_access
  sev-low  : http_scan, connection_attempt
"""
from django import template

register = template.Library()

_SEVERITY = {
    'ip_blocked': 'sev-crit',
    'port_scan': 'sev-high',
    'brute_force': 'sev-high',
    'http_brute_force': 'sev-med',
    'admin_panel_access': 'sev-med',
    'http_scan': 'sev-low',
    'connection_attempt': 'sev-low',
}


@register.filter
def severity(attack_type):
    return _SEVERITY.get(attack_type, 'sev-low')
