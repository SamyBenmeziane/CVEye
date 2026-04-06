from collections import defaultdict

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from app_core.models import Cible, Scan, Service
from app_scan.scanner import SocketScanner
from app_security.models import Vulnerability
from app_security.services.nvd_client import NVDClient
from .forms import TargetForm


def compute_risk_label(vulnerability_count):
    if vulnerability_count >= 5:
        return "Critique"
    if vulnerability_count >= 3:
        return "Élevé"
    if vulnerability_count >= 1:
        return "Moyen"
    return "Faible"


def get_server_header(headers):
    if not isinstance(headers, dict):
        return None

    for key, value in headers.items():
        if str(key).lower() == "server" and value:
            return value
    return None


def build_scan_details(scan_obj):
    if not scan_obj:
        return []

    services = (
        Service.objects.filter(scan=scan_obj)
        .prefetch_related("vulnerabilities")
        .order_by("port")
    )

    details = []

    for service in services:
        headers = service.en_tetes if isinstance(service.en_tetes, dict) else {}
        headers_without_server = {
            k: v for k, v in headers.items() if str(k).lower() != "server"
        }

        server_header = get_server_header(headers)

        display_version = (
            server_header
            or service.version
            or service.produit
            or "N/A"
        )

        vulnerabilities = list(service.vulnerabilities.all())

        details.append({
            "port": service.port,
            "service": service.nom_service,
            "display_version": display_version,
            "banner": service.banniere,
            "product": service.produit,
            "headers_without_server": headers_without_server,
            "vulnerabilities": vulnerabilities,
        })

    return details


def get_service_lookup_key(service_obj):
    if service_obj.cpe_name:
        return f"cpe_name::{service_obj.cpe_name}"

    if service_obj.cpe_match_string:
        return f"cpe_match::{service_obj.cpe_match_string}"

    produit = (service_obj.produit or "").strip().lower()
    version = (service_obj.version or "").strip().lower()
    nom_service = (service_obj.nom_service or "").strip().lower()

    if produit or version or nom_service:
        return f"service::{nom_service}|{produit}|{version}"

    return None


def lookup_vulnerabilities_for_service(service_obj, nvd_client):
    lookup_key = get_service_lookup_key(service_obj)
    if not lookup_key:
        return []

    try:
        lookup = nvd_client.lookup_service_vulnerabilities(service_obj)
    except Exception:
        return []

    vulnerabilities = []
    for vuln in lookup.get("vulnerabilities", []):
        vulnerabilities.append({
            "cve_id": vuln.get("cve_id"),
            "published": parse_datetime(vuln.get("published")) if vuln.get("published") else None,
            "description": vuln.get("description", ""),
            "severity": vuln.get("severity") or "",
            "score": vuln.get("score"),
            "correlation_type": lookup.get("correlation_type", "none"),
            "query_value": lookup.get("query_value") or "",
        })

    return vulnerabilities


def attach_vulnerabilities_to_service(service_obj, vulnerabilities):
    for vuln in vulnerabilities:
        if not vuln.get("cve_id"):
            continue

        Vulnerability.objects.get_or_create(
            service=service_obj,
            cve_id=vuln["cve_id"],
            defaults={
                "published": vuln["published"],
                "description": vuln["description"],
                "severity": vuln["severity"],
                "score": vuln["score"],
                "correlation_type": vuln["correlation_type"],
                "query_value": vuln["query_value"],
            },
        )


def execute_scan_for_target(target, user):
    scan_obj = Scan.objects.create(
        cible=target,
        owner=user,
        statut="en_cours",
        version_scanner="SocketScanner",
        ports_scannes=65535,
        ports_ouverts=0,
    )

    try:
        scanner = SocketScanner(target.adresse)
        resultat_scan = scanner.run()

        ouverts = 0
        created_services = []

        for port, item in resultat_scan.items():
            ouverts += 1

            service_obj = Service.objects.create(
                scan=scan_obj,
                port=item.get("port", port),
                protocole="tcp",
                nom_service=item.get("service", "unknown"),
                produit=item.get("produit"),
                version=item.get("version"),
                banniere=item.get("banniere"),
                en_tetes=item.get("headers", {}),
                etat="open",
                cpe_match_string=item.get("cpe_match_string"),
                cpe_name=item.get("cpe_name"),
            )
            created_services.append(service_obj)

        grouped_services = defaultdict(list)
        for service_obj in created_services:
            lookup_key = get_service_lookup_key(service_obj)
            if lookup_key:
                grouped_services[lookup_key].append(service_obj)

        nvd_client = NVDClient()

        for _, services_group in grouped_services.items():
            representative_service = services_group[0]
            vulnerabilities = lookup_vulnerabilities_for_service(representative_service, nvd_client)

            if not vulnerabilities:
                continue

            for service_obj in services_group:
                attach_vulnerabilities_to_service(service_obj, vulnerabilities)

        scan_obj.statut = "complete"
        scan_obj.date_fin = timezone.now()
        scan_obj.ports_ouverts = ouverts
        scan_obj.save()

        return {
            "erreur": None,
            "scan_obj": scan_obj,
        }

    except Exception as exc:
        scan_obj.statut = "echoue"
        scan_obj.date_fin = timezone.now()
        scan_obj.message_erreur = str(exc)
        scan_obj.save()

        return {
            "erreur": f"Erreur pendant le scan : {exc}",
            "scan_obj": scan_obj,
        }


def build_scans_context(user, selected_scan=None, target_id=None, status_filter=None):
    scans_qs = (
        Scan.objects.filter(owner=user)
        .select_related("cible")
        .annotate(
            vulnerability_count=Count("services__vulnerabilities", distinct=True),
            service_count=Count("services", distinct=True),
        )
        .order_by("-date_debut")
    )

    if target_id:
        scans_qs = scans_qs.filter(cible_id=target_id)

    if status_filter:
        scans_qs = scans_qs.filter(statut=status_filter)

    scans = list(scans_qs)

    for scan in scans:
        if scan.date_fin and scan.date_debut:
            scan.duration_seconds = int((scan.date_fin - scan.date_debut).total_seconds())
        else:
            scan.duration_seconds = None

    if selected_scan is None and scans:
        selected_scan = scans[0]

    if selected_scan:
        selected_scan = (
            Scan.objects.filter(owner=user, pk=selected_scan.pk)
            .select_related("cible")
            .annotate(
                vulnerability_count=Count("services__vulnerabilities", distinct=True),
                service_count=Count("services", distinct=True),
            )
            .first()
        )

    if selected_scan and selected_scan.date_fin and selected_scan.date_debut:
        selected_scan.duration_seconds = int((selected_scan.date_fin - selected_scan.date_debut).total_seconds())
    else:
        selected_scan.duration_seconds = None

    details = build_scan_details(selected_scan)

    return {
        "scans": scans,
        "selected_scan": selected_scan,
        "resultat": details,
        "targets": Cible.objects.filter(owner=user).order_by("adresse"),
        "selected_target_id": str(target_id) if target_id else "",
        "selected_status": status_filter or "",
    }


@login_required
def dashboard_view(request):
    scans = (
        Scan.objects.filter(owner=request.user)
        .select_related("cible")
        .annotate(
            vulnerability_count=Count("services__vulnerabilities", distinct=True),
            service_count=Count("services", distinct=True),
        )
        .order_by("-date_debut")
    )

    latest_scans = list(scans[:5])

    total_scans = scans.count()
    total_targets = Cible.objects.filter(owner=request.user).count()
    completed_scans = scans.filter(statut="complete").count()
    failed_scans = scans.filter(statut="echoue").count()
    total_services = Service.objects.filter(scan__owner=request.user).count()
    total_vulnerabilities = (
        Service.objects.filter(scan__owner=request.user)
        .aggregate(total=Count("vulnerabilities", distinct=True))
        .get("total", 0)
    )

    context = {
        "total_scans": total_scans,
        "total_targets": total_targets,
        "completed_scans": completed_scans,
        "failed_scans": failed_scans,
        "total_services": total_services,
        "total_vulnerabilities": total_vulnerabilities,
        "latest_scans": latest_scans,
    }
    return render(request, "app_dashboard/dashboard.html", context)


@login_required
def targets_page_view(request):
    form = TargetForm(request.POST or None, user=request.user)

    if request.method == "POST" and form.is_valid():
        target = form.save(commit=False)
        target.owner = request.user
        target.save()
        messages.success(request, "La cible a été ajoutée avec succès.")
        return redirect("targets")

    search = request.GET.get("q", "").strip()

    targets_qs = Cible.objects.filter(owner=request.user).order_by("adresse")

    if search:
        targets_qs = targets_qs.filter(
            Q(adresse__icontains=search)
            | Q(description__icontains=search)
        )

    targets = list(targets_qs)

    for target in targets:
        last_scan = (
            Scan.objects.filter(cible=target, owner=request.user)
            .order_by("-date_debut")
            .first()
        )

        target.last_scan = last_scan
        target.last_scan_date = last_scan.date_debut if last_scan else None

        if last_scan:
            target.service_count = Service.objects.filter(scan=last_scan).count()
            target.vulnerability_count = (
                Service.objects.filter(scan=last_scan)
                .aggregate(total=Count("vulnerabilities", distinct=True))
                .get("total", 0)
            )
        else:
            target.service_count = 0
            target.vulnerability_count = 0

        target.risk_label = compute_risk_label(target.vulnerability_count)

        if not target.active:
            target.display_status = "Offline"
        elif target.vulnerability_count >= 3:
            target.display_status = "Warning"
        else:
            target.display_status = "Online"

    context = {
        "form": form,
        "targets": targets,
        "search": search,
    }
    return render(request, "app_dashboard/targets_page.html", context)


@login_required
def launch_target_scan_view(request, target_id):
    if request.method != "POST":
        return redirect("targets")

    target = get_object_or_404(Cible, id=target_id, owner=request.user)

    execution = execute_scan_for_target(target, request.user)

    if execution["erreur"]:
        messages.error(request, execution["erreur"])
        return redirect("targets")

    messages.success(request, f"Scan terminé pour {target.adresse}.")
    return redirect("scans")


@login_required
def scans_page_view(request):
    target_id = request.GET.get("target", "").strip()
    status_filter = request.GET.get("status", "").strip()

    context = build_scans_context(
        request.user,
        selected_scan=None,
        target_id=target_id or None,
        status_filter=status_filter or None,
    )
    return render(request, "app_dashboard/scans_page.html", context)