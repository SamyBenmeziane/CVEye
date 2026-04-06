from django.shortcuts import render
from django.utils import timezone
import ipaddress
import time

from app_scan.scanner import SocketScanner
from app_core.models import Cible, Scan, Service


def est_ip(valeur):
    try:
        ipaddress.ip_address(valeur)
        return True
    except ValueError:
        return False


def ip_autorisee(ip_str):
    if ip_str.lower() == "localhost":
        return False

    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False
        return True
    except ValueError:
        return True


def format_duration(seconds):
    seconds = int(seconds)
    if seconds <= 1:
        return f"{seconds} seconde"
    return f"{seconds} secondes"


def get_server_header(headers):
    if not isinstance(headers, dict):
        return None

    for key, value in headers.items():
        if str(key).lower() == "server" and value:
            return value
    return None


def clean_version(raw_version, headers):
    server_value = get_server_header(headers)

    if server_value:
        return server_value

    if raw_version and str(raw_version).strip() not in {"???", "unknown", "-"}:
        return raw_version

    return "-"


def clean_headers_without_server(headers):
    if not isinstance(headers, dict):
        return {}

    cleaned = {}
    for key, value in headers.items():
        if str(key).lower() != "server":
            cleaned[key] = value
    return cleaned


def scans_page_view(request):
    resultat = None
    addr_ip = None
    erreur = None
    duration = None
    now_display = None
    alert_count = 0

    if request.method == "POST":
        addr_ip = request.POST.get("addr_ip", "").strip()

        if not addr_ip:
            erreur = "Veuillez entrer une adresse IP ou un domaine."
            return render(request, "app_dashboard/scans_page.html", {
                "resultat": resultat,
                "addr_ip": addr_ip,
                "erreur": erreur,
                "duration": duration,
                "now_display": now_display,
                "alert_count": alert_count,
            })

        if not ip_autorisee(addr_ip):
            erreur = "Cette adresse n'est pas autorisée pour le scan."
            return render(request, "app_dashboard/scans_page.html", {
                "resultat": resultat,
                "addr_ip": addr_ip,
                "erreur": erreur,
                "duration": duration,
                "now_display": now_display,
                "alert_count": alert_count,
            })

        scan_obj = None
        start_time = time.time()

        try:
            type_cible = "ip" if est_ip(addr_ip) else "domaine"

            cible_obj, _ = Cible.objects.get_or_create(
                adresse=addr_ip,
                defaults={"type_cible": type_cible}
            )

            scan_obj = Scan.objects.create(
                cible=cible_obj,
                statut="en_cours",
                ports_scannes=65535,
                version_scanner="SocketScanner"
            )

            scanner = SocketScanner(addr_ip)
            scanner.run()

            resultat = sorted(
                scanner.resultat.values(),
                key=lambda x: x["port"]
            )

            nb_ports_ouverts = 0
            resultat_affichage = []

            for service_data in resultat:
                headers = service_data.get("headers", {}) or {}
                version_affichee = clean_version(service_data.get("version"), headers)
                headers_sans_server = clean_headers_without_server(headers)

                Service.objects.create(
                    scan=scan_obj,
                    port=service_data.get("port"),
                    protocole="tcp",
                    nom_service=service_data.get("service", "unknown"),
                    produit=service_data.get("product") or service_data.get("produit"),
                    version=version_affichee,
                    banniere=service_data.get("banner", ""),
                    en_tetes=headers_sans_server,
                    etat="open"
                )

                service_data["display_version"] = version_affichee
                service_data["headers_without_server"] = headers_sans_server

                resultat_affichage.append(service_data)
                nb_ports_ouverts += 1

            resultat = resultat_affichage

            scan_obj.statut = "complete"
            scan_obj.date_fin = timezone.now()
            scan_obj.ports_ouverts = nb_ports_ouverts
            scan_obj.save()

            duration = format_duration(time.time() - start_time)
            now_display = timezone.localtime().strftime("%d/%m/%Y %H:%M")

        except Exception as e:
            if scan_obj:
                scan_obj.statut = "echoue"
                scan_obj.date_fin = timezone.now()
                scan_obj.message_erreur = str(e)
                scan_obj.save()

            erreur = str(e)
            duration = "N/A"
            now_display = timezone.localtime().strftime("%d/%m/%Y %H:%M")

    return render(request, "app_dashboard/scans_page.html", {
        "resultat": resultat,
        "addr_ip": addr_ip,
        "erreur": erreur,
        "duration": duration,
        "now_display": now_display,
        "alert_count": alert_count,
    })