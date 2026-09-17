
from django.urls import path
from . import views

urlpatterns = [
    path('api/attacks/', views.receive_attack, name='receive_attack'),
    path('', views.dashboard, name='dashboard'),
    path('api/latest/', views.latest_attacks, name='latest_attacks'),
    path('api/stats/', views.stats_api, name='stats_api'),
    path('api/geo/', views.geo_api, name='geo_api'),
    path('map/', views.threat_map, name='threat_map'),
    path('logs/', views.attack_logs, name='attack_logs'),
    path('attackers/', views.attackers, name='attackers'),
    path('attackers/<str:ip>/', views.attacker_detail, name='attacker_detail'),
    path('reports/', views.reports_page, name='reports'),
    path('export/csv/', views.export_csv, name='export_csv'),
    path('report/', views.forensic_report, name='forensic_report'),
]
