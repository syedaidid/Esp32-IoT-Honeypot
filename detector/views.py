from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.db.models import Count, Max, Min, Q
from django.core.paginator import Paginator
from django.utils import timezone
from django.conf import settings
from django.core.cache import cache
from datetime import timedelta
import json, csv, hmac, ipaddress
from .models import AttackLog, AttackerGeo, SENSOR_IDS
from django.http import HttpResponse
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import ipaddress

VALID_ATTACK_TYPES = {
    'port_scan', 'brute_force', 'connection_attempt',
    'http_scan', 'http_brute_force', 'admin_panel_access',
    'ip_blocked',
}
MAX_PAYLOAD_LEN = 500
INGEST_RATE_LIMIT = 60       # allowed requests per IP per window
INGEST_RATE_WINDOW = 60      # seconds

# ── GeoIP (free ip-api.com, cached per-IP in AttackerGeo) ─────────────────────
GEO_LOOKUP_TIMEOUT = 5
GEO_MAX_PER_HOUR = 200        # stay well under the free tier (45 req/min)

def _geo_rate_ok():
    hits = cache.get('geo:lookups', 0)
    return hits < GEO_MAX_PER_HOUR

def lookup_geo(attacker_ip):
    """Return (lat, lon, country, city, country_code, isp) or None.

    Cached per IP in AttackerGeo; private/bogon and failed lookups are marked
    lookup_failed so they are never retried. Runs only when the hourly budget
    allows — geo enrichment must never block or spam.
    """
    cached = AttackerGeo.objects.filter(attacker_ip=attacker_ip).first()
    if cached:
        return None if cached.lookup_failed else cached

    addr = ipaddress.ip_address(attacker_ip)
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
        AttackerGeo.objects.update_or_create(
            attacker_ip=attacker_ip, defaults={'lookup_failed': True})
        return None
    if not _geo_rate_ok():
        return None  # budget spent — skip silently, retry on a later event

    try:
        import urllib.request
        url = f'http://ip-api.com/json/{attacker_ip}?fields=status,country,countryCode,city,lat,lon,isp'
        with urllib.request.urlopen(url, timeout=GEO_LOOKUP_TIMEOUT) as r:
            data = json.loads(r.read().decode())
        if data.get('status') != 'success':
            raise ValueError(data.get('message', 'lookup failed'))
        geo, _ = AttackerGeo.objects.update_or_create(
            attacker_ip=attacker_ip,
            defaults={
                'country': (data.get('country') or '')[:80] or None,
                'country_code': data.get('countryCode') or None,
                'city': (data.get('city') or '')[:80] or None,
                'latitude': data.get('lat'),
                'longitude': data.get('lon'),
                'isp': (data.get('isp') or '')[:120] or None,
                'lookup_failed': False,
            })
        cache.set('geo:lookups', cache.get('geo:lookups', 0) + 1, 3600)
        return geo
    except Exception:
        # failed lookups are NOT marked permanently failed (transient errors),
        # but consume no further retries within this hour window
        cache.set('geo:lookups', cache.get('geo:lookups', 0) + 1, 3600)
        return None

# ── Receive attack from ESP32 / VPS sensor (ingest — shared API key) ──
@csrf_exempt
@require_POST
def receive_attack(request):
    # API key auth: firmware must present the shared secret in X-API-Key
    expected = getattr(settings, 'HONEYPOT_API_KEY', '')
    if expected:
        provided = request.headers.get('X-API-Key', '')
        if not hmac.compare_digest(provided, expected):
            print(f"[AUTH FAIL] Bad X-API-Key from {request.META.get('REMOTE_ADDR', '?')}")
            return JsonResponse({'status': 'error', 'message': 'Unauthorized'}, status=403)

    # Per-IP rate limit (cache-backed, 60 req/min — generous for one device)
    client_ip = request.META.get('REMOTE_ADDR', '')
    cache_key = f'ingest:{client_ip}'
    hits = cache.get(cache_key, 0)
    if hits >= INGEST_RATE_LIMIT:
        print(f"[RATE LIMITED] {client_ip}")
        return JsonResponse({'status': 'error', 'message': 'Rate limit exceeded'}, status=429)
    cache.set(cache_key, hits + 1, INGEST_RATE_WINDOW)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Malformed JSON: {e}")
        print(f"[RAW BODY] {request.body}")
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON'}, status=400)

    attacker_ip = data.get('attacker_ip', '')
    port = data.get('port', None)
    attack_type = data.get('attack_type', '')
    payload = data.get('payload', '')
    event_id = str(data.get('event_id', ''))[:64]
    sensor = str(data.get('sensor', 'esp32-lan'))[:20]

    # Idempotency: if this event_id was already ingested, return the original row
    if event_id:
        existing = AttackLog.objects.filter(event_id=event_id).first()
        if existing:
            print(f"[DUPLICATE] event_id={event_id} -> row {existing.id}")
            return JsonResponse({'status': 'duplicate', 'id': existing.id}, status=200)

    # Validate IP
    try:
        ipaddress.ip_address(attacker_ip)
    except (ValueError, TypeError):
        print(f"[REJECTED] Invalid IP: {attacker_ip!r}")
        return JsonResponse({'status': 'error', 'message': 'Invalid attacker_ip'}, status=400)

    # Validate sensor id (unknown sensors are rejected, not defaulted — a typo
    # in firmware/config should surface loudly instead of corrupting analytics)
    if sensor not in SENSOR_IDS:
        print(f"[REJECTED] Unknown sensor: {sensor!r}")
        return JsonResponse({'status': 'error', 'message': 'Invalid sensor'}, status=400)

    # Validate port
    if not isinstance(port, int) or not (0 <= port <= 65535):
        print(f"[REJECTED] Invalid port: {port!r}")
        return JsonResponse({'status': 'error', 'message': 'Invalid port'}, status=400)

    # Validate attack_type against known set
    if attack_type not in VALID_ATTACK_TYPES:
        print(f"[REJECTED] Unknown attack_type: {attack_type!r}")
        return JsonResponse({'status': 'error', 'message': 'Invalid attack_type'}, status=400)

    # Sanitize/cap payload
    if not isinstance(payload, str):
        payload = str(payload)
    payload = payload[:MAX_PAYLOAD_LEN]

    log = AttackLog.objects.create(
        attacker_ip=attacker_ip,
        port=port,
        attack_type=attack_type,
        payload=payload,
        event_id=event_id or None,
        sensor=sensor,
    )

    # Geo-enrichment (best-effort, cached; private IPs skipped instantly)
    geo = lookup_geo(attacker_ip) if sensor == 'vps-sensor' else None
    loc = f" ({geo.city}, {geo.country_code})" if geo else ''
    print(f"[ATTACK LOGGED] {log.attack_type} from {log.attacker_ip}{loc} on port {log.port} (event_id={event_id or '-'}, sensor={sensor})")
    return JsonResponse({'status': 'ok', 'id': log.id}, status=201)

@login_required
def dashboard(request):
    logs = AttackLog.objects.all().order_by('-timestamp')[:50]
    total = AttackLog.objects.count()
    unique_ips = AttackLog.objects.values('attacker_ip').distinct().count()
    
    # Stats by attack type
    by_type = AttackLog.objects.values('attack_type').annotate(
        count=Count('attack_type')).order_by('-count')
    
    # Stats by IP
    by_ip = AttackLog.objects.values('attacker_ip').annotate(
        count=Count('attacker_ip')).order_by('-count')[:5]
    
    # Stats by port
    by_port = AttackLog.objects.values('port').annotate(
        count=Count('port')).order_by('-count')[:5]

    # Attacks per hour over the last 24 hours
    now = timezone.now()
    since = now - timedelta(hours=24)
    hourly = [0] * 24
    recent_ts = AttackLog.objects.filter(timestamp__gte=since).values_list('timestamp', flat=True)
    for ts in recent_ts:
        diff = int((now - timezone.localtime(ts)).total_seconds() // 3600)
        bucket = 23 - min(23, diff)
        hourly[bucket] += 1
    time_labels = [(timezone.localtime(now) - timedelta(hours=i)).strftime('%H:%M')
                   for i in range(23, -1, -1)]

    # Repeatedly-blocked (banned) attackers
    banned = (
        AttackLog.objects.filter(attack_type='ip_blocked')
        .values('attacker_ip')
        .annotate(last=Max('timestamp'), attempts=Count('id'))
        .order_by('-last')[:10]
    )

    context = {
        'logs': logs,
        'total': total,
        'unique_ips': unique_ips,
        'by_type': by_type,
        'by_ip': by_ip,
        'by_port': by_port,
        'banned': banned,
        'hourly': hourly,
        'time_labels': time_labels,
        'latest': logs[0] if logs else None,
    }
    return render(request, 'detector/dashboard.html', context)

# ── API for live refresh ──
@login_required
def latest_attacks(request):
    logs = AttackLog.objects.all().order_by('-timestamp')[:10]
    data = [{
        'id': log.id,
        'attacker_ip': log.attacker_ip,
        'port': log.port,
        'attack_type': log.attack_type,
        'sensor': log.sensor,
        'payload': log.payload,
        'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    } for log in logs]
    return JsonResponse({'attacks': data})

@login_required
@login_required
def stats_api(request):
    """Live board numbers for the dashboard auto-refresh."""
    total = AttackLog.objects.count()
    unique_ips = AttackLog.objects.values('attacker_ip').distinct().count()

    by_type = list(AttackLog.objects.values('attack_type')
                   .annotate(count=Count('attack_type')).order_by('-count'))
    by_port = list(AttackLog.objects.values('port')
                   .annotate(count=Count('port')).order_by('-count')[:5])
    top_ip = (AttackLog.objects.values('attacker_ip')
              .annotate(count=Count('attacker_ip')).order_by('-count').first())
    banned = list(
        AttackLog.objects.filter(attack_type='ip_blocked')
        .values('attacker_ip')
        .annotate(last=Max('timestamp'), attempts=Count('id'))
        .order_by('-last')[:10]
    )
    for b in banned:
        b['last'] = b['last'].strftime('%Y-%m-%d %H:%M:%S') if b['last'] else None

    return JsonResponse({
        'total': total,
        'unique_ips': unique_ips,
        'by_type': by_type,
        'by_port': by_port,
        'top_ip': top_ip,
        'banned': banned,
    })

# ── Geolocation data for the threat map ──
@login_required
def geo_api(request):
    """Attack origins joined with cached geo lookups — feeds the Leaflet map."""
    rows = (
        AttackLog.objects
        .exclude(attacker_ip__startswith='192.168.')
        .exclude(attacker_ip__startswith='10.')
        .exclude(attacker_ip__startswith='172.16.')
        .values('attacker_ip', 'sensor')
        .annotate(count=Count('id'), last_seen=Max('timestamp'))
        .order_by('-count')[:200]
    )
    geos = {g.attacker_ip: g for g in AttackerGeo.objects.all()}
    data = []
    for r in rows:
        g = geos.get(r['attacker_ip'])
        if g and g.latitude is not None and g.longitude is not None:
            data.append({
                'ip': r['attacker_ip'],
                'lat': g.latitude,
                'lon': g.longitude,
                'count': r['count'],
                'city': g.city,
                'country': g.country,
                'country_code': g.country_code,
                'isp': g.isp,
                'sensor': r['sensor'],
                'last_seen': r['last_seen'].strftime('%Y-%m-%d %H:%M:%S'),
            })
    return JsonResponse({'origins': data})

# ── Full attack log (paginated + filterable) ──
@login_required
def attack_logs(request):
    qs = AttackLog.objects.all()

    q = request.GET.get('q', '').strip()
    atype = request.GET.get('type', '').strip()
    port = request.GET.get('port', '').strip()
    sensor = request.GET.get('sensor', '').strip()
    date_from = request.GET.get('from', '').strip()
    date_to = request.GET.get('to', '').strip()

    if q:
        qs = qs.filter(Q(attacker_ip__icontains=q) | Q(payload__icontains=q))
    if atype:
        qs = qs.filter(attack_type=atype)
    if sensor:
        qs = qs.filter(sensor=sensor)
    if port:
        try:
            qs = qs.filter(port=int(port))
        except ValueError:
            pass
    if date_from:
        qs = qs.filter(timestamp__date__gte=date_from)
    if date_to:
        qs = qs.filter(timestamp__date__lte=date_to)

    qs = qs.order_by('-timestamp')
    paginator = Paginator(qs, 25)
    page = paginator.get_page(request.GET.get('page'))

    types = AttackLog.objects.values_list('attack_type', flat=True).distinct().order_by('attack_type')
    sensors = AttackLog.objects.values_list('sensor', flat=True).distinct().order_by('sensor')

    context = {
        'page': page,
        'types': types,
        'sensors': sensors,
        'f': {'q': q, 'type': atype, 'port': port, 'sensor': sensor, 'from': date_from, 'to': date_to},
    }
    return render(request, 'detector/logs.html', context)

# ── Attacker summary (unique IPs) ──
@login_required
def attackers(request):
    rows = list(
        AttackLog.objects.values('attacker_ip')
        .annotate(total=Count('id'),
                  first=Min('timestamp'),
                  last=Max('timestamp'),
                  methods=Count('attack_type', distinct=True))
        .order_by('-total')
    )
    blocked_map = dict(
        AttackLog.objects.filter(attack_type='ip_blocked')
        .values('attacker_ip').annotate(n=Count('id'))
        .values_list('attacker_ip', 'n')
    )
    for r in rows:
        r['blocked'] = blocked_map.get(r['attacker_ip'], 0)

    paginator = Paginator(rows, 25)
    page = paginator.get_page(request.GET.get('page'))
    return render(request, 'detector/attackers.html', {'page': page})

# ── Single attacker forensic profile ──
@login_required
def attacker_detail(request, ip):
    logs = AttackLog.objects.filter(attacker_ip=ip).order_by('-timestamp')
    total = logs.count()

    if total:
        first = logs.last().timestamp
        last = logs.first().timestamp
    else:
        first = last = None

    by_type = list(logs.values('attack_type').annotate(
        c=Count('attack_type')).order_by('-c'))
    by_port = list(logs.values('port').annotate(
        c=Count('port')).order_by('-c'))
    by_sensor = list(logs.values('sensor').annotate(
        c=Count('sensor')).order_by('-c'))
    blocked_hits = logs.filter(attack_type='ip_blocked').count()

    # Hourly activity for this IP over the last 24h
    now = timezone.now()
    hourly = [0] * 24
    recent_ts = logs.filter(timestamp__gte=now - timedelta(hours=24)).values_list('timestamp', flat=True)
    for ts in recent_ts:
        diff = int((now - timezone.localtime(ts)).total_seconds() // 3600)
        hourly[23 - min(23, diff)] += 1
    time_labels = [(timezone.localtime(now) - timedelta(hours=i)).strftime('%H:%M')
                   for i in range(23, -1, -1)]

    paginator = Paginator(logs, 25)
    page = paginator.get_page(request.GET.get('page'))

    context = {
        'ip': ip,
        'total': total,
        'first': first,
        'last': last,
        'by_type': by_type,
        'by_port': by_port,
        'by_sensor': by_sensor,
        'blocked_hits': blocked_hits,
        'hourly': hourly,
        'time_labels': time_labels,
        'page': page,
    }
    return render(request, 'detector/attacker_detail.html', context)

# ── Threat map (attack origins) ──
@login_required
def threat_map(request):
    """Full-page geolocation view of attack origins."""
    geo_rows = (
        AttackerGeo.objects.filter(lookup_failed=False,
                                   latitude__isnull=False)
        .order_by('country_code')
    )
    by_country = (
        AttackerGeo.objects.filter(lookup_failed=False)
        .values('country', 'country_code')
        .annotate(attackers=Count('id'))
        .order_by('-attackers')[:10]
    )
    context = {
        'geo_rows': geo_rows,
        'by_country': by_country,
        'geo_count': geo_rows.count(),
    }
    return render(request, 'detector/map.html', context)

# ── Reports / export center ──
@login_required
def reports_page(request):
    total = AttackLog.objects.count()
    unique_ips = AttackLog.objects.values('attacker_ip').distinct().count()
    first = AttackLog.objects.first()
    last = AttackLog.objects.last()
    context = {
        'total': total,
        'unique_ips': unique_ips,
        'first': first.timestamp if first else None,
        'last': last.timestamp if last else None,
    }
    return render(request, 'detector/reports.html', context)

@login_required
def export_csv(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="honeypot_attack_log.csv"'
    writer = csv.writer(response)
    writer.writerow(['id', 'attacker_ip', 'sensor', 'port', 'attack_type', 'payload', 'timestamp'])
    for log in AttackLog.objects.all().order_by('-timestamp'):
        writer.writerow([log.id, log.attacker_ip, log.sensor, log.port, log.attack_type,
                         (log.payload or '').replace('\r', ' ').replace('\n', ' '),
                         log.timestamp.strftime('%Y-%m-%d %H:%M:%S')])
    return response

def forensic_report(request):
    # Fetch all data
    logs = AttackLog.objects.all().order_by('-timestamp')
    total = logs.count()
    by_type = AttackLog.objects.values('attack_type').annotate(
        count=Count('attack_type')).order_by('-count')
    by_ip = AttackLog.objects.values('attacker_ip').annotate(
        count=Count('attacker_ip')).order_by('-count')[:10]

    # Setup PDF response
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="honeypot_forensic_report.pdf"'

    doc = SimpleDocTemplate(
        response,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm
    )

    styles = getSampleStyleSheet()
    elements = []

    # ── Title ──
    title_style = ParagraphStyle(
        'title', fontSize=20, alignment=TA_CENTER,
        textColor=colors.HexColor('#1F3864'), fontName='Helvetica-Bold',
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'subtitle', fontSize=11, alignment=TA_CENTER,
        textColor=colors.HexColor('#555555'), fontName='Helvetica',
        spaceAfter=4
    )
    heading_style = ParagraphStyle(
        'heading', fontSize=13, textColor=colors.HexColor('#1F3864'),
        fontName='Helvetica-Bold', spaceBefore=16, spaceAfter=8
    )
    normal_style = ParagraphStyle(
        'normal2', fontSize=10, textColor=colors.HexColor('#333333'),
        fontName='Helvetica', spaceAfter=4, leading=16
    )

    elements.append(Paragraph("FORENSIC INCIDENT REPORT", title_style))
    elements.append(Paragraph("IoT Honeypot System — ESP32 Based Intrusion Detection", subtitle_style))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#1F3864')))
    elements.append(Spacer(1, 0.4*cm))

    # ── Section 1: Summary ──
    elements.append(Paragraph("1. Executive Summary", heading_style))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#CCCCCC')))
    elements.append(Spacer(1, 0.2*cm))

    first = logs.last()
    last = logs.first()
    first_seen = first.timestamp.strftime('%Y-%m-%d %H:%M:%S') if first else 'N/A'
    last_seen = last.timestamp.strftime('%Y-%m-%d %H:%M:%S') if last else 'N/A'

    summary_data = [
        ['Field', 'Value'],
        ['Total Attack Events Logged', str(total)],
        ['First Attack Detected', first_seen],
        ['Most Recent Attack', last_seen],
        ['Unique Attack Types', str(by_type.count())],
        ['Unique Attacker IPs', str(AttackLog.objects.values('attacker_ip').distinct().count())],
        ['Monitored Ports', 'Port 23 (Telnet), Port 80 (HTTP)'],
        ['Honeypot Device', 'ESP32 NodeMCU IoT Honeypot'],
    ]

    summary_table = Table(summary_data, colWidths=[7*cm, 10*cm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1F3864')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('BACKGROUND', (0,1), (0,-1), colors.HexColor('#EBF0FA')),
        ('FONTNAME', (0,1), (0,-1), 'Helvetica-Bold'),
        ('ROWBACKGROUNDS', (1,1), (-1,-1), [colors.white, colors.HexColor('#F5F8FF')]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CCCCCC')),
        ('PADDING', (0,0), (-1,-1), 8),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 0.4*cm))

    # ── Section 2: Attack Type Breakdown ──
    elements.append(Paragraph("2. Attack Type Analysis", heading_style))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#CCCCCC')))
    elements.append(Spacer(1, 0.2*cm))

    type_data = [['Attack Type', 'Count', 'Percentage', 'Description']]
    descriptions = {
        'port_scan': 'Rapid multi-port connection — nmap or automated scanner',
        'brute_force': 'Repeated login attempts with credentials on Telnet',
        'connection_attempt': 'Single connection with no login attempt',
        'http_scan': 'HTTP GET request probing the fake admin panel',
        'http_brute_force': 'HTTP POST login attempt on admin panel',
        'admin_panel_access': 'Direct access attempt to /admin endpoint',
        'ip_blocked': 'Repeat connection refused from an IP banned after a detected port scan',
    }

    for t in by_type:
        pct = f"{(t['count']/total*100):.1f}%" if total > 0 else "0%"
        desc = descriptions.get(t['attack_type'], 'Unknown attack pattern')
        type_data.append([t['attack_type'], str(t['count']), pct, desc])

    type_table = Table(type_data, colWidths=[4*cm, 2*cm, 2.5*cm, 8.5*cm])
    type_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2E5EAA')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F5F8FF')]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CCCCCC')),
        ('PADDING', (0,0), (-1,-1), 7),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    elements.append(type_table)
    elements.append(Spacer(1, 0.4*cm))

    # ── Section 3: Top Attacker IPs ──
    elements.append(Paragraph("3. Top Attacker IP Addresses", heading_style))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#CCCCCC')))
    elements.append(Spacer(1, 0.2*cm))

    ip_data = [['Rank', 'IP Address', 'Total Attacks', 'Percentage']]
    for i, ip in enumerate(by_ip, 1):
        pct = f"{(ip['count']/total*100):.1f}%" if total > 0 else "0%"
        ip_data.append([str(i), ip['attacker_ip'], str(ip['count']), pct])

    ip_table = Table(ip_data, colWidths=[2*cm, 5*cm, 4*cm, 6*cm])
    ip_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E8449')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F5F8FF')]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CCCCCC')),
        ('PADDING', (0,0), (-1,-1), 7),
        ('ALIGN', (0,0), (0,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    elements.append(ip_table)
    elements.append(Spacer(1, 0.4*cm))

    # ── Section 4: Full Attack Log ──
    elements.append(Paragraph("4. Full Attack Event Log", heading_style))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#CCCCCC')))
    elements.append(Spacer(1, 0.2*cm))

    log_data = [['#', 'IP Address', 'Port', 'Attack Type', 'Payload', 'Timestamp']]
    for log in logs[:100]:  # max 100 rows
        log_data.append([
            str(log.id),
            log.attacker_ip,
            str(log.port),
            log.attack_type,
            (log.payload[:30] + '...') if len(log.payload) > 30 else log.payload,
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        ])

    log_table = Table(log_data, colWidths=[1*cm, 3.5*cm, 1.5*cm, 3.5*cm, 4*cm, 4.5*cm])
    log_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#333333')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 7.5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F9F9F9')]),
        ('GRID', (0,0), (-1,-1), 0.3, colors.HexColor('#DDDDDD')),
        ('PADDING', (0,0), (-1,-1), 5),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    elements.append(log_table)
    elements.append(Spacer(1, 0.4*cm))

    # ── Section 5: Conclusion ──
    elements.append(Paragraph("5. Conclusion & Recommendations", heading_style))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#CCCCCC')))
    elements.append(Spacer(1, 0.2*cm))

    conclusion_text = f"""
    This forensic report documents {total} attack events detected by the ESP32-based IoT Honeypot
    system deployed on the office network. The honeypot simulated a vulnerable IoT device exposing
    Telnet (port 23) and HTTP (port 80) services to attract unauthorized access attempts.
    The most common attack type detected was {by_type[0]['attack_type'] if by_type else 'N/A'},
    accounting for {f"{(by_type[0]['count']/total*100):.1f}%" if by_type and total > 0 else 'N/A'}
    of all recorded events. All attack evidence has been preserved in the database with full
    forensic details including IP address, timestamp, port, attack classification, and payload.
    """
    elements.append(Paragraph(conclusion_text.strip(), normal_style))
    elements.append(Spacer(1, 0.3*cm))

    elements.append(Paragraph("Recommendations:", ParagraphStyle(
        'rec', fontSize=10, fontName='Helvetica-Bold',
        textColor=colors.HexColor('#1F3864'), spaceAfter=6
    )))

    recommendations = [
        "1. Block all IP addresses identified as port scanners at the firewall level.",
        "2. Implement rate limiting on Telnet and HTTP services to slow brute force attempts.",
        "3. Enable real-time email alerts for critical attack events.",
        "4. Review attack logs weekly to identify new attack patterns.",
        "5. Consider expanding honeypot to monitor additional ports (21, 22, 443, 8080).",
    ]
    for rec in recommendations:
        elements.append(Paragraph(rec, normal_style))

    elements.append(Spacer(1, 0.5*cm))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#1F3864')))
    elements.append(Spacer(1, 0.2*cm))
    elements.append(Paragraph(
        f"Report generated by IoT Honeypot System | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | CONFIDENTIAL",
        ParagraphStyle('footer', fontSize=8, alignment=TA_CENTER, textColor=colors.HexColor('#888888'))
    ))

    doc.build(elements)
    return response
