from django.contrib import admin
from .models import Cible, Scan, Service, InstallationConfig


@admin.register(Cible)
class CibleAdmin(admin.ModelAdmin):
    list_display = (
        "adresse",
        "type_cible",
        "active",
        "surveillance_active",
        "periodicite_scan",
        "dernier_scan_le",
        "prochain_scan_le",
        "date_creation",
    )
    search_fields = ("adresse",)
    list_filter = ("type_cible", "active", "surveillance_active", "periodicite_scan")


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = (
        "cible",
        "statut",
        "server_hs",
        "date_debut",
        "date_fin",
        "ports_ouverts",
        "version_scanner",
    )
    search_fields = ("cible__adresse",)
    list_filter = ("statut", "server_hs", "date_debut")


@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ("scan", "port", "protocole", "nom_service", "produit", "version", "etat")
    search_fields = ("scan__cible__adresse", "nom_service", "produit", "version")
    list_filter = ("protocole", "etat", "nom_service")


@admin.register(InstallationConfig)
class InstallationConfigAdmin(admin.ModelAdmin):
    list_display = (
        "site_name",
        "is_installed",
        "installed_at",
        "smtp_host",
        "smtp_port",
        "smtp_from_email",
        "updated_at",
    )