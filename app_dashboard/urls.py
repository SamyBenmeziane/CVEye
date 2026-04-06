from django.urls import path
from .views import (
    dashboard_view,
    scans_page_view,
    targets_page_view,
    launch_target_scan_view,
)

urlpatterns = [
    path("dashboard/", dashboard_view, name="dashboard"),
    path("targets/", targets_page_view, name="targets"),
    path("targets/<uuid:target_id>/scan/", launch_target_scan_view, name="launch_target_scan"),
    path("scans/", scans_page_view, name="scans"),
]