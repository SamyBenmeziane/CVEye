from django.urls import path
from .views import scans_page_view

urlpatterns = [
    path("", scans_page_view, name="scans_page"),
]