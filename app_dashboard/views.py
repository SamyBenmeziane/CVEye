import logging
import threading
from functools import wraps

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.db import close_old_connections, connections
from django.db.models import Count, OuterRef, Q, Subquery
from django.http import HttpResponse, HttpResponseNotAllowed, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from app_accounts.models import BannedIP, UserProfile
from app_accounts.utils import purge_user_sessions, send_account_approved_email, sync_user_activation_state
from app_core.models import Cible, Scan, Service
from app_scan.progress import get_scan_progress, pop_scan_progress
from app_scan.scan_execution import create_scan_record, execute_scan_from_record
from app_scan.scheduler_utils import calculer_prochain_scan
from app_security.models import Vulnerability
from .risk_utils import (
    compute_vulnerability_count_risk_label,
    normalize_severity_label,
    SEVERITY_HIGH_LABEL,
)
from .reporting import build_target_report_filename, generate_target_report_pdf
from .forms import TargetForm

from app_security.services.manual_search import (
    SEARCH_MODE_CONFIG,
    FIELD_LABELS,
    manual_vulnerability_search,
)


logger = logging.getLogger(__name__)
SCAN_STALE_TIMEOUT = int(getattr(settings, "SCAN_STALE_TIMEOUT", 900))
SEVERITY_ORDER = ["Critique", SEVERITY_HIGH_LABEL, "Moyenne", "Faible", "Inconnue"]


def superadmin_required(view_func):
    """Décorateur restreignant l'accès aux super administrateurs.

    Redirige vers la connexion si non authentifié, vers le tableau de bord sinon.
    """
    @wraps(view_func)
    def wrapped(request, *args, **kwargs):
        """Vérifie les droits et redirige si l'utilisateur n'est pas super administrateur."""
        if not request.user.is_authenticated:
            return redirect("accounts:login")
        if not request.user.is_superuser:
            messages.error(request, "Accès réservé au super administrateur.")
            return redirect("dashboard")
        return view_func(request, *args, **kwargs)

    return wrapped


def _run_scan_in_background(scan_id):
    """Exécute un scan depuis un thread secondaire en gérant les connexions base de données."""
    close_old_connections()
    try:
        execute_scan_from_record(scan_id)
    except Exception:
        logger.exception("Erreur lors de l execution du scan %s", scan_id)
    finally:
        connections.close_all()


def _start_scan_thread(scan_id):
    """Démarre un thread démon pour exécuter le scan sans bloquer la vue."""
    scan_thread = threading.Thread(
        target=_run_scan_in_background,
        args=(str(scan_id),),
        name=f"scan-worker-{scan_id}",
        daemon=True,
    )
    scan_thread.start()


def _is_scan_stale(scan_obj):
    """Indique si un scan actif a dépassé le délai SCAN_STALE_TIMEOUT sans se terminer."""
    if not scan_obj or scan_obj.statut not in {"en_attente", "en_cours"} or not scan_obj.date_debut:
        return False

    age_seconds = (timezone.now() - scan_obj.date_debut).total_seconds()
    return age_seconds >= SCAN_STALE_TIMEOUT


def _expire_scan(scan_obj):
    """Marque un scan bloqué comme échoué et supprime sa progression en mémoire."""
    if not scan_obj:
        return

    pop_scan_progress(scan_obj.pk)
    Scan.objects.filter(pk=scan_obj.pk).update(
        statut="echoue",
        date_fin=timezone.now(),
        message_erreur="Le scan precedent a expire. Un nouveau scan est necessaire.",
    )
    scan_obj.statut = "echoue"
    scan_obj.date_fin = timezone.now()
    scan_obj.message_erreur = "Le scan precedent a expire. Un nouveau scan est necessaire."


def get_server_header(headers):
    """Extrait la valeur de l'en-tête HTTP 'Server' depuis un dictionnaire d'en-têtes (insensible à la casse)."""
    if not isinstance(headers, dict):
        return None

    for key, value in headers.items():
        if str(key).lower() == "server" and value:
            return value
    return None


def build_empty_severity_counts():
    """Retourne un dictionnaire initialisé à zéro pour chaque niveau de sévérité connu."""
    return {label: 0 for label in SEVERITY_ORDER}


def annotate_targets_with_latest_scan(targets_qs, owner, status=None):
    """Annote un queryset de cibles avec l'identifiant et la date du scan le plus récent par cible."""
    latest_scan_qs = Scan.objects.filter(owner=owner, cible=OuterRef("pk"))
    if status:
        latest_scan_qs = latest_scan_qs.filter(statut=status)
    latest_scan_qs = latest_scan_qs.order_by("-date_debut")

    return targets_qs.annotate(
        latest_scan_id=Subquery(latest_scan_qs.values("id")[:1]),
        latest_scan_date=Subquery(latest_scan_qs.values("date_debut")[:1]),
    )


def load_scans_with_metrics(scan_ids, owner):
    """Charge un ensemble de scans en annotant chacun du nombre de services et de vulnérabilités."""
    if not scan_ids:
        return {}

    scans = (
        Scan.objects.filter(owner=owner, id__in=scan_ids)
        .select_related("cible")
        .annotate(
            vulnerability_count=Count("services__vulnerabilities", distinct=True),
            service_count=Count("services", distinct=True),
        )
    )
    return {str(scan.id): scan for scan in scans}


def build_scan_details(scan_obj):
    """Construit la liste détaillée des services d'un scan pour l'affichage dans le template.

    Pour chaque service : en-têtes HTTP, bannière, vulnérabilités avec compteurs
    de sévérité, version affichée et sévérité dominante.
    """
    if not scan_obj:
        return []

    services = (
        Service.objects.filter(scan=scan_obj)
        .prefetch_related("vulnerabilities")
        .order_by("port")
    )

    details = []
    MAX_CVE = 5
    MAX_HEADERS = 4
    MAX_BANNER = 140

    for service in services:
        headers = service.en_tetes if isinstance(service.en_tetes, dict) else {}
        # On sort lentete server a part pour en faire la version affichee en priorite
        headers_without_server = {
            k: v for k, v in headers.items() if str(k).lower() != "server"
        }

        server_header = get_server_header(headers)

        display_version = (
            server_header
            or service.produit
            or service.version
            or "N/A"
        )

        vulnerabilities = list(service.vulnerabilities.all())
        severity_counts = build_empty_severity_counts()
        for vulnerability in vulnerabilities:
            severity_counts[normalize_severity_label(vulnerability.severity)] += 1

        banner = service.banniere or ""
        headers_list = list(headers_without_server.items())

        details.append({
            "port": service.port,
            "service": service.nom_service,
            "display_version": display_version,
            "banner": banner,
            "banner_short": banner[:MAX_BANNER],
            "banner_rest": banner[MAX_BANNER:],
            "product": service.produit,
            "version": service.version,
            "protocol": service.protocole.upper() if service.protocole else "TCP",
            "headers_without_server": headers_without_server,
            "headers_visible": headers_list[:MAX_HEADERS],
            "headers_hidden": headers_list[MAX_HEADERS:],
            "vulnerabilities": vulnerabilities,
            "vulnerabilities_visible": vulnerabilities[:MAX_CVE],
            "vulnerabilities_hidden": vulnerabilities[MAX_CVE:],
            "severity_counts": severity_counts,
            "total_vulnerabilities": len(vulnerabilities),
            "dominant_severity": next(
                (label for label in SEVERITY_ORDER if severity_counts[label] > 0),
                "Inconnue",
            ),
            "severities_str": "|".join(
                label for label in ["Critique", "Élevée", "Moyenne", "Faible"]
                if severity_counts.get(label, 0) > 0
            ),
        })

    return details


def hydrate_scan_metrics(scan_obj):
    """Ajoute l'attribut duration_seconds au scan en calculant la durée écoulée depuis le début."""
    if not scan_obj:
        return None

    end_time = scan_obj.date_fin
    if end_time is None and scan_obj.statut in {"en_cours", "en_attente"}:
        end_time = timezone.now()

    if scan_obj.date_debut and end_time:
        scan_obj.duration_seconds = max(0, int((end_time - scan_obj.date_debut).total_seconds()))
    else:
        scan_obj.duration_seconds = None

    return scan_obj


def build_machine_vulnerabilities_context(user, target_id=None, severity_filter=None, exposed_only=False):
    """Construit le contexte complet de la page des vulnérabilités par machine.

    Agrège pour chaque cible les vulnérabilités du dernier scan terminé, les compteurs
    par sévérité, le niveau de risque et le statut en ligne/hors ligne.
    Supporte le filtrage par cible, par sévérité et par machines exposées uniquement.
    """
    targets_qs = Cible.objects.filter(owner=user).order_by("adresse")
    if target_id:
        targets_qs = targets_qs.filter(id=target_id)

    targets = list(annotate_targets_with_latest_scan(targets_qs, user, status="complete"))
    latest_scan_ids = [target.latest_scan_id for target in targets if target.latest_scan_id]
    latest_scans_by_id = load_scans_with_metrics(latest_scan_ids, user)

    vulnerabilities_by_target = {str(target.id): [] for target in targets}
    if latest_scan_ids:
        vulnerabilities_qs = (
            Vulnerability.objects.filter(service__scan_id__in=latest_scan_ids)
            .select_related("service", "service__scan", "service__scan__cible")
            .order_by("service__scan__cible__adresse", "-score", "cve_id")
        )

        for vulnerability in vulnerabilities_qs:
            normalized_severity = normalize_severity_label(vulnerability.severity)
            if severity_filter and normalized_severity != severity_filter:
                continue

            target_key = str(vulnerability.service.scan.cible_id)
            vulnerabilities_by_target.setdefault(target_key, []).append({
                "cve_id": vulnerability.cve_id,
                "severity": normalized_severity,
                "score": vulnerability.score,
                "description": vulnerability.description,
                "published": vulnerability.published,
                "details_url": f"https://nvd.nist.gov/vuln/detail/{vulnerability.cve_id}",
                "service_name": vulnerability.service.nom_service,
                "port": vulnerability.service.port,
                "product": vulnerability.service.produit,
                "version": vulnerability.service.version,
            })

    machine_rows = []

    for target in targets:
        latest_scan = latest_scans_by_id.get(str(target.latest_scan_id)) if target.latest_scan_id else None
        vulnerabilities = vulnerabilities_by_target.get(str(target.id), [])
        severity_counts = {
            "Critique": 0,
            "Élevée": 0,
            "Moyenne": 0,
            "Faible": 0,
            "Inconnue": 0,
        }
        for vulnerability in vulnerabilities:
            severity_counts[vulnerability["severity"]] += 1

        if latest_scan:
            risk_label = compute_vulnerability_count_risk_label(len(vulnerabilities))
            status_label = "Hors ligne" if latest_scan.server_hs else "En ligne"
        else:
            risk_label = "Faible"
            status_label = "Jamais scannée"

        machine_rows.append({
            "target": target,
            "latest_scan": latest_scan,
            "vulnerabilities": vulnerabilities,
            "vulnerability_count": len(vulnerabilities),
            "severity_counts": severity_counts,
            "risk_label": risk_label,
            "status_label": status_label,
        })

    if severity_filter:
        machine_rows = [row for row in machine_rows if row["vulnerability_count"] > 0]

    if exposed_only:
        machine_rows = [row for row in machine_rows if row["vulnerability_count"] > 0]

    def _bucket(row):
        if row["severity_counts"]["Critique"] > 0:
            return 0
        if row["vulnerability_count"] > 0:
            return 1
        return 2

    machine_rows.sort(key=lambda row: (_bucket(row), -row["vulnerability_count"], row["target"].adresse))

    total_vulnerabilities = sum(row["vulnerability_count"] for row in machine_rows)
    machines_with_vulnerabilities = sum(1 for row in machine_rows if row["vulnerability_count"] > 0)
    critical_machines = sum(1 for row in machine_rows if row["severity_counts"]["Critique"] > 0)
    top_exposed_service = ""
    latest_scan_reference = None
    service_exposure_counts = {}

    for row in machine_rows:
        if row["latest_scan"] and (
            latest_scan_reference is None
            or row["latest_scan"].date_debut > latest_scan_reference.date_debut
        ):
            latest_scan_reference = row["latest_scan"]

        for vulnerability in row["vulnerabilities"]:
            service_name = vulnerability["service_name"] or "unknown"
            service_exposure_counts[service_name] = service_exposure_counts.get(service_name, 0) + 1

    if service_exposure_counts:
        top_exposed_service = max(service_exposure_counts.items(), key=lambda item: item[1])[0]

    return {
        "machine_rows": machine_rows,
        "targets": targets,
        "selected_target_id": str(target_id) if target_id else "",
        "selected_severity": severity_filter or "",
        "selected_exposed": bool(exposed_only),
        "total_machines": len(machine_rows),
        "machines_with_vulnerabilities": machines_with_vulnerabilities,
        "total_vulnerabilities": total_vulnerabilities,
        "critical_machines": critical_machines,
        "top_exposed_service": top_exposed_service,
        "latest_scan_reference": latest_scan_reference,
    }
def build_scans_context(user, selected_scan=None, selected_scan_id=None, target_id=None, status_filter=None):
    """Prépare le contexte de la page de liste des scans avec filtres et résumé des compteurs."""
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
        hydrate_scan_metrics(scan)

    if selected_scan is None and selected_scan_id:
        selected_scan = next(
            (scan for scan in scans if str(scan.pk) == str(selected_scan_id)),
            None,
        )

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

        if selected_scan:
            hydrate_scan_metrics(selected_scan)

    details = build_scan_details(selected_scan)
    critical_scan_ids = set(
        Vulnerability.objects.filter(service__scan__owner=user, service__scan__in=scans_qs)
        .filter(Q(severity__iexact="critical") | Q(severity__iexact="critique"))
        .values_list("service__scan_id", flat=True)
        .distinct()
    )

    return {
        "scans": scans,
        "selected_scan": selected_scan,
        "resultat": details,
        "targets": Cible.objects.filter(owner=user).order_by("adresse"),
        "selected_target_id": str(target_id) if target_id else "",
        "selected_status": status_filter or "",
        "selected_scan_id": str(selected_scan.pk) if selected_scan else "",
        "scan_summary": {
            "total": len(scans),
            "in_progress": sum(1 for scan in scans if scan.statut in {"en_cours", "en_attente"}),
            "failed": sum(1 for scan in scans if scan.statut == "echoue"),
            "critical": sum(1 for scan in scans if scan.pk in critical_scan_ids),
        },
    }


def build_target_detail_context(user, target, selected_scan_id=None):
    """Prépare le contexte de la page de détail d'une cible avec historique des scans et métriques."""
    scans = list(
        Scan.objects.filter(owner=user, cible=target)
        .select_related("cible")
        .annotate(
            vulnerability_count=Count("services__vulnerabilities", distinct=True),
            service_count=Count("services", distinct=True),
        )
        .order_by("-date_debut")
    )

    for scan in scans:
        hydrate_scan_metrics(scan)

    latest_scan = scans[0] if scans else None
    selected_scan = latest_scan

    if selected_scan_id:
        selected_scan = next(
            (scan for scan in scans if str(scan.pk) == str(selected_scan_id)),
            latest_scan,
        )

    selected_scan_details = build_scan_details(selected_scan)

    latest_scan_details = []
    latest_service_count = 0
    latest_vulnerability_count = 0
    latest_status = "Jamais scannée"
    latest_risk_label = "Faible"

    if latest_scan:
        latest_scan_details = build_scan_details(latest_scan)
        latest_service_count = latest_scan.service_count
        latest_vulnerability_count = latest_scan.vulnerability_count
        latest_risk_label = compute_vulnerability_count_risk_label(latest_vulnerability_count)

        if latest_scan.statut in {"en_cours", "en_attente"}:
            latest_status = latest_scan.statut
        elif latest_scan.server_hs:
            latest_status = "Hors ligne"
        elif latest_vulnerability_count >= 1:
            latest_status = "Critique"
        else:
            latest_status = "En ligne"

    selected_severity_totals = {"Critique": 0, "Élevée": 0, "Moyenne": 0, "Faible": 0}
    for _row in selected_scan_details:
        for _label in selected_severity_totals:
            selected_severity_totals[_label] += _row["severity_counts"].get(_label, 0)

    return {
        "target": target,
        "scan_count": len(scans),
        "all_scans": scans,
        "latest_scan": latest_scan,
        "latest_scan_details": latest_scan_details,
        "latest_service_count": latest_service_count,
        "latest_vulnerability_count": latest_vulnerability_count,
        "latest_status": latest_status,
        "latest_risk_label": latest_risk_label,
        "selected_scan": selected_scan,
        "selected_scan_details": selected_scan_details,
        "selected_scan_id": str(selected_scan.pk) if selected_scan else "",
        "scan_history": scans[1:] if latest_scan else [],
        "selected_severity_totals": selected_severity_totals,
    }
    

@login_required
def dashboard_view(request):
    """Affiche le tableau de bord principal avec les statistiques globales et les derniers scans."""
    if request.user.is_superuser:
        return redirect("admin_console")

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
    critical_vulnerabilities = Vulnerability.objects.filter(
        service__scan__owner=request.user
    ).filter(
        Q(severity__iexact="critical") | Q(severity__iexact="critique")
    ).count()

    context = {
        "total_scans": total_scans,
        "total_targets": total_targets,
        "completed_scans": completed_scans,
        "failed_scans": failed_scans,
        "total_services": total_services,
        "total_vulnerabilities": total_vulnerabilities,
        "critical_vulnerabilities": critical_vulnerabilities,
        "latest_scans": latest_scans,
    }
    return render(request, "app_dashboard/dashboard.html", context)


@login_required
def targets_page_view(request):
    """Affiche la liste des cibles et traite l'ajout d'une nouvelle cible via formulaire."""
    form = TargetForm(request.POST or None, user=request.user)

    if request.method == "POST" and form.is_valid():
        target = form.save(commit=False)
        target.owner = request.user

        if target.surveillance_active and target.periodicite_scan:
            target.prochain_scan_le = calculer_prochain_scan(
                timezone.now(),
                target.periodicite_scan,
            )
        else:
            target.periodicite_scan = None
            target.prochain_scan_le = None

        target.full_clean()
        target.save()
        messages.success(request, "Le serveur a été ajouté avec succès.")
        return redirect("targets")

    search = request.GET.get("q", "").strip()

    targets_qs = Cible.objects.filter(owner=request.user).order_by("adresse")

    if search:
        targets_qs = targets_qs.filter(
            Q(adresse__icontains=search)
            | Q(description__icontains=search)
        )

    targets = list(annotate_targets_with_latest_scan(targets_qs, request.user))
    latest_scan_ids = [target.latest_scan_id for target in targets if target.latest_scan_id]
    latest_scans_by_id = load_scans_with_metrics(latest_scan_ids, request.user)

    scan_counts_by_target = {
        str(row["cible_id"]): row["count"]
        for row in (
            Scan.objects.filter(owner=request.user, cible_id__in=[target.id for target in targets])
            .values("cible_id")
            .annotate(count=Count("id"))
        )
    }

    for target in targets:
        last_scan = latest_scans_by_id.get(str(target.latest_scan_id)) if target.latest_scan_id else None
        target.last_scan = last_scan
        target.last_scan_date = target.latest_scan_date if last_scan else None

        if last_scan:
            target.service_count = last_scan.service_count
            target.scan_count = scan_counts_by_target.get(str(target.id), 0)
            target.vulnerability_count = last_scan.vulnerability_count
        else:
            target.scan_count = scan_counts_by_target.get(str(target.id), 0)
            target.service_count = 0
            target.vulnerability_count = 0

        target.risk_label = compute_vulnerability_count_risk_label(target.vulnerability_count)

        if not target.active:
            target.display_status = "Désactivée"
        elif last_scan and last_scan.server_hs:
            target.display_status = "Hors ligne"
        elif target.vulnerability_count >= 1:
            target.display_status = "Critique"
        else:
            target.display_status = "En ligne"

    context = {
        "form": form,
        "targets": targets,
        "search": search,
    }
    return render(request, "app_dashboard/targets_page.html", context)



@login_required
def launch_target_scan_async_view(request, target_id):
    """Démarre un scan asynchrone pour une cible, en réutilisant un scan actif non bloqué si existant."""
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    target = get_object_or_404(Cible, id=target_id, owner=request.user)

    existing_scan = (
        Scan.objects.filter(
            owner=request.user,
            cible=target,
            statut__in=["en_attente", "en_cours"],
        )
        .order_by("-date_debut")
        .first()
    )

    if existing_scan and _is_scan_stale(existing_scan):
        _expire_scan(existing_scan)
        existing_scan = None

    if existing_scan:
        scan_obj = existing_scan
    else:
        scan_obj = create_scan_record(target, request.user)
        _start_scan_thread(scan_obj.id)

    redirect_url = f"/targets/{target.id}/?scan={scan_obj.id}"

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return JsonResponse(
            {
                "id": str(scan_obj.id),
                "message": f"Scan demarre pour {target.adresse}.",
                "redirect_url": redirect_url,
            }
        )

    messages.success(request, f"Scan demarre pour {target.adresse}.")
    return redirect(redirect_url)


@login_required
def launch_target_port_scan_async_view(request, target_id, port):
    """Démarre un scan ciblé sur un port précis pour une cible donnée."""
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    if port < 1 or port > 65535:
        return JsonResponse({"error": "Port invalide."}, status=400)

    target = get_object_or_404(Cible, id=target_id, owner=request.user)
    scan_obj = create_scan_record(target, request.user, ports=[port])
    _start_scan_thread(scan_obj.id)

    redirect_url = f"/targets/{target.id}/?scan={scan_obj.id}"
    message = f"Scan ciblé démarré pour {target.adresse} sur le port {port}."

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return JsonResponse(
            {
                "id": str(scan_obj.id),
                "message": message,
                "redirect_url": redirect_url,
            }
        )

    messages.success(request, message)
    return redirect(redirect_url)


@login_required
def scans_page_view(request):
    """Affiche la page de liste des scans avec filtres optionnels sur la cible et le statut."""
    target_id = request.GET.get("target", "").strip()
    status_filter = request.GET.get("status", "").strip()
    selected_scan_id = request.GET.get("selected_scan", "").strip()

    context = build_scans_context(
        request.user,
        selected_scan=None,
        selected_scan_id=selected_scan_id or None,
        target_id=target_id or None,
        status_filter=status_filter or None,
    )
    return render(request, "app_dashboard/scans_page.html", context)


@login_required
def target_detail_view(request, target_id):
    """Affiche la page de détail d'une cible avec l'historique des scans."""
    target = get_object_or_404(Cible, id=target_id, owner=request.user)
    selected_scan_id = request.GET.get("scan", "").strip()

    context = build_target_detail_context(
        request.user,
        target,
        selected_scan_id=selected_scan_id or None,
    )
    return render(request, "app_dashboard/target_detail.html", context)


@login_required
def target_report_options_view(request, target_id):
    """Affiche la page de choix des options avant la génération du rapport PDF."""
    target = get_object_or_404(Cible, id=target_id, owner=request.user)
    scans_count = Scan.objects.filter(owner=request.user, cible=target).count()

    return render(
        request,
        "app_dashboard/target_report_options.html",
        {
            "target": target,
            "scans_count": scans_count,
            "default_count": min(3, scans_count) if scans_count else 1,
        },
    )


@login_required
def download_target_report_pdf_view(request, target_id):
    """Génère et retourne le rapport PDF d'une cible selon la portée choisie (latest, count, all)."""
    target = get_object_or_404(Cible, id=target_id, owner=request.user)
    if request.method != "POST":
        return redirect("target_report_options", target_id=target.id)

    report_scope = request.POST.get("report_scope", "latest").strip().lower()
    scans_qs = (
        Scan.objects.filter(owner=request.user, cible=target)
        .select_related("cible")
        .order_by("-date_debut")
    )

    total_scans = scans_qs.count()

    if report_scope == "all":
        scans = list(scans_qs)
    elif report_scope == "count":
        count_raw = request.POST.get("count", "1").strip()
        try:
            requested_count = int(count_raw)
        except (TypeError, ValueError):
            requested_count = 1

        requested_count = max(1, min(requested_count, total_scans or 1))
        scans = list(scans_qs[:requested_count])
    else:
        scans = list(scans_qs[:1])

    if not scans:
        messages.warning(request, "Aucun scan n'est disponible pour générer un rapport PDF.")
        return redirect("target_report_options", target_id=target.id)

    pdf_content = generate_target_report_pdf(target, scans, request.user)
    filename = build_target_report_filename(target, len(scans))

    response = HttpResponse(pdf_content, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@login_required
def vulnerabilities_page_view(request):
    """Affiche la page des vulnérabilités par machine avec filtres sur la cible et la sévérité."""
    target_id = request.GET.get("target", "").strip()
    severity_filter = request.GET.get("severity", "").strip()
    exposed_only = request.GET.get("exposed", "").strip() == "1"

    allowed_severities = set(SEVERITY_ORDER)
    if severity_filter not in allowed_severities:
        severity_filter = ""

    context = build_machine_vulnerabilities_context(
        request.user,
        target_id=target_id or None,
        severity_filter=severity_filter or None,
        exposed_only=exposed_only,
    )
    return render(request, "app_dashboard/vulnerabilities_page.html", context)


@login_required
def scan_progress_view(request):
    """Retourne en JSON l'avancement des scans demandés, en expirant les scans bloqués détectés."""
    requested_ids = [
        scan_id.strip()
        for scan_id in request.GET.get("ids", "").split(",")
        if scan_id.strip()
    ]

    scans_qs = (
        Scan.objects.filter(owner=request.user)
        .select_related("cible")
        .only(
            "id",
            "statut",
            "ports_ouverts",
            "ports_scannes",
            "ports_scannes_courant",
            "date_debut",
            "date_fin",
            "message_erreur",
            "cible__adresse",
        )
        .order_by("-date_debut")
    )

    if requested_ids:
        scans_qs = scans_qs.filter(id__in=requested_ids)
    else:
        scans_qs = scans_qs.filter(statut__in=["en_attente", "en_cours"])

    scans_payload = []
    for scan in scans_qs:
        live_progress = get_scan_progress(scan.id)
        if not live_progress and _is_scan_stale(scan):
            _expire_scan(scan)

        total_ports = int((live_progress or {}).get("ports_scanned_total", scan.ports_scannes or 0))
        current_ports = int((live_progress or {}).get("ports_scanned_current", scan.ports_scannes_courant or 0))
        ports_open = int((live_progress or {}).get("ports_open", scan.ports_ouverts or 0))
        status = (live_progress or {}).get("status", scan.statut)
        error_message = (live_progress or {}).get("error_message", scan.message_erreur or "")

        if total_ports < 0:
            total_ports = 0
        current_ports = max(0, min(current_ports, total_ports or current_ports))

        progress_percent = 0
        if total_ports > 0:
            progress_percent = min(100, round((current_ports / total_ports) * 100, 1))

        started_at = (live_progress or {}).get("started_at")
        start_time = parse_datetime(started_at) if started_at else scan.date_debut
        if start_time and timezone.is_naive(start_time):
            start_time = timezone.make_aware(start_time, timezone.get_current_timezone())

        end_time = scan.date_fin or timezone.now()
        duration_seconds = None
        if start_time and end_time:
            duration_seconds = max(0, int((end_time - start_time).total_seconds()))

        scans_payload.append({
            "id": str(scan.id),
            "target_address": scan.cible.adresse,
            "status": status,
            "ports_open": ports_open,
            "ports_scanned_current": current_ports,
            "ports_scanned_total": total_ports,
            "progress_percent": progress_percent,
            "duration_seconds": duration_seconds,
            "finished": status in {"complete", "echoue"},
            "error_message": error_message,
        })

    return JsonResponse({"scans": scans_payload})

@login_required
def edit_target_view(request, target_id):
    """Affiche et traite le formulaire d'édition d'une cible existante."""
    target = get_object_or_404(Cible, id=target_id, owner=request.user)
    form = TargetForm(request.POST or None, instance=target, user=request.user)

    if request.method == "POST" and form.is_valid():
        updated_target = form.save(commit=False)

        if updated_target.surveillance_active and updated_target.periodicite_scan:
            if not updated_target.prochain_scan_le:
                updated_target.prochain_scan_le = calculer_prochain_scan(
                    timezone.now(),
                    updated_target.periodicite_scan,
                )
        else:
            updated_target.periodicite_scan = None
            updated_target.prochain_scan_le = None

        updated_target.full_clean()
        updated_target.save()
        messages.success(request, "Le serveur a été mis à jour.")
        return redirect("targets")

    return render(
        request,
        "app_dashboard/target_edit.html",
        {
            "form": form,
            "target": target,
        },
    )


@login_required
def delete_target_view(request, target_id):
    """Supprime une cible et toutes ses données associées (scans, services, vulnérabilités)."""
    if request.method != "POST":
        return redirect("targets")

    target = get_object_or_404(Cible, id=target_id, owner=request.user)
    target.delete()
    messages.success(request, "Le serveur a été supprimé.")
    return redirect("targets")


@login_required
def scan_details_view(request, scan_id):
    """Retourne en JSON les détails complets d'un scan avec ses services et vulnérabilités."""
    scan = (
        Scan.objects.filter(owner=request.user, id=scan_id)
        .select_related("cible")
        .annotate(
            vulnerability_count=Count("services__vulnerabilities", distinct=True),
            service_count=Count("services", distinct=True),
        )
        .first()
    )

    if not scan:
        return JsonResponse({"error": "Scan introuvable."}, status=404)

    details = build_scan_details(scan)

    return JsonResponse(
        {
            "id": str(scan.id),
            "target_id": str(scan.cible.id),
            "target_address": scan.cible.adresse,
            "status": scan.statut,
            "ports_open": scan.ports_ouverts,
            "vulnerability_count": scan.vulnerability_count,
            "details": [
                {
                    "port": item["port"],
                    "service": item["service"] or "unknown",
                    "display_version": item["display_version"],
                    "banner": item["banner"] or "",
                    "product": item["product"] or "",
                    "version": item["version"] or "",
                    "protocol": item["protocol"],
                    "headers_without_server": item["headers_without_server"],
                    "severity_counts": item["severity_counts"],
                    "total_vulnerabilities": item["total_vulnerabilities"],
                    "dominant_severity": item["dominant_severity"],
                    "vulnerabilities": [
                        {
                            "cve_id": vuln.cve_id,
                            "severity": normalize_severity_label(vuln.severity),
                        }
                        for vuln in item["vulnerabilities"]
                    ],
                }
                for item in details
            ],
        }
    )


@superadmin_required
def admin_console_view(request):
    """Affiche la console d'administration avec la liste des utilisateurs, scans, cibles et IP bannies."""
    search = request.GET.get("q", "").strip()
    owner_filter = request.GET.get("owner", "").strip()
    status_filter = request.GET.get("status", "").strip()

    users_base_qs = (
        User.objects.filter(is_superuser=False)
        .select_related("userprofile")
        .annotate(
            scan_count=Count("owned_scans", distinct=True),
            target_count=Count("owned_targets", distinct=True),
        )
        .order_by("first_name", "last_name", "username")
    )

    if search:
        users_base_qs = users_base_qs.filter(
            Q(first_name__icontains=search)
            | Q(last_name__icontains=search)
            | Q(username__icontains=search)
            | Q(email__icontains=search)
        )

    users = list(users_base_qs)
    for user in users:
        profile, _ = UserProfile.objects.get_or_create(user=user)
        user.userprofile = profile
        sync_user_activation_state(user, profile=profile)

    def _matches_status_filter(user_obj):
        profile = user_obj.userprofile
        if status_filter == "active":
            return profile.admin_approved and profile.email_verified and user_obj.is_active and not profile.admin_disabled
        if status_filter == "disabled":
            return profile.admin_disabled
        if status_filter == "pending":
            return profile.email_verified and not profile.admin_approved and not profile.admin_disabled
        if status_filter == "unverified":
            return not profile.email_verified and not profile.admin_disabled
        return True

    if status_filter:
        users = [user for user in users if _matches_status_filter(user)]

    selected_owner = next((user for user in users if str(user.pk) == owner_filter), None)

    scans_qs = (
        Scan.objects.select_related("owner", "cible")
        .annotate(
            vulnerability_count=Count("services__vulnerabilities", distinct=True),
            service_count=Count("services", distinct=True),
        )
        .order_by("-date_debut")
    )

    targets_qs = (
        Cible.objects.select_related("owner")
        .annotate(scan_count=Count("scans", distinct=True))
        .order_by("-date_creation")
    )

    if owner_filter:
        scans_qs = scans_qs.filter(owner_id=owner_filter)
        targets_qs = targets_qs.filter(owner_id=owner_filter)
    elif search:
        scans_qs = scans_qs.filter(
            Q(owner__first_name__icontains=search)
            | Q(owner__last_name__icontains=search)
            | Q(owner__username__icontains=search)
            | Q(cible__adresse__icontains=search)
        )
        targets_qs = targets_qs.filter(
            Q(owner__first_name__icontains=search)
            | Q(owner__last_name__icontains=search)
            | Q(owner__username__icontains=search)
            | Q(adresse__icontains=search)
        )

    scans = list(scans_qs[:50])
    for scan in scans:
        hydrate_scan_metrics(scan)

    targets = list(targets_qs[:50])
    scan_groups_map = {}
    for scan in scans:
        group_key = str(scan.cible_id)
        if group_key not in scan_groups_map:
            scan_groups_map[group_key] = {
                "target": scan.cible,
                "scan_count": 0,
                "owners_count": 0,
                "latest_scan": scan,
                "vulnerability_count": 0,
                "owners": {},
                "scans": [],
            }

        group = scan_groups_map[group_key]
        group["scan_count"] += 1
        group["vulnerability_count"] += scan.vulnerability_count
        group["owners"][scan.owner_id] = scan.owner
        group["scans"].append(scan)

    scan_groups = []
    for group in scan_groups_map.values():
        group["owners_count"] = len(group["owners"])
        scan_groups.append(group)

    target_ids = [target.id for target in targets]
    service_counts_by_target = {
        str(row["scan__cible_id"]): row["count"]
        for row in Service.objects.filter(scan__cible_id__in=target_ids)
        .values("scan__cible_id")
        .annotate(count=Count("id"))
    }
    vulnerability_counts_by_target = {
        str(row["service__scan__cible_id"]): row["count"]
        for row in Vulnerability.objects.filter(service__scan__cible_id__in=target_ids)
        .values("service__scan__cible_id")
        .annotate(count=Count("id"))
    }
    inventory_groups_map = {}
    for target in targets:
        owner_key = str(target.owner_id)
        if owner_key not in inventory_groups_map:
            inventory_groups_map[owner_key] = {
                "owner": target.owner,
                "target_count": 0,
                "scan_count": 0,
                "service_count": 0,
                "vulnerability_count": 0,
                "targets": [],
            }

        group = inventory_groups_map[owner_key]
        group["target_count"] += 1
        group["scan_count"] += target.scan_count
        group["service_count"] += service_counts_by_target.get(str(target.id), 0)
        group["vulnerability_count"] += vulnerability_counts_by_target.get(str(target.id), 0)
        group["targets"].append(target)

    inventory_groups = list(inventory_groups_map.values())
    banned_ips = list(BannedIP.objects.order_by("-banned_at"))

    pending_users = [
        user for user in users
        if user.userprofile.email_verified
        and not user.userprofile.admin_approved
        and not user.userprofile.admin_disabled
    ]

    context = {
        "search": search,
        "owner_filter": owner_filter,
        "status_filter": status_filter,
        "selected_owner": selected_owner,
        "users": users,
        "pending_users": pending_users,
        "scans": scans,
        "targets": targets,
        "scan_groups": scan_groups,
        "inventory_groups": inventory_groups,
        "banned_ips": banned_ips,
        "total_users": User.objects.filter(is_superuser=False).count(),
        "pending_approvals_count": UserProfile.objects.filter(
            user__is_superuser=False,
            email_verified=True,
            admin_approved=False,
            admin_disabled=False,
        ).count(),
        "active_users_count": UserProfile.objects.filter(
            user__is_superuser=False,
            email_verified=True,
            admin_approved=True,
            admin_disabled=False,
            user__is_active=True,
        ).count(),
        "disabled_users_count": UserProfile.objects.filter(
            user__is_superuser=False,
            admin_disabled=True,
        ).count(),
        "total_scans_global": Scan.objects.count(),
        "total_targets_global": Cible.objects.count(),
    }
    return render(request, "app_dashboard/admin_console.html", context)


@superadmin_required
def approve_user_view(request, user_id):
    """Approuve un compte utilisateur, met à jour son état actif et envoie l'email de notification."""
    if request.method != "POST":
        return redirect("admin_console")

    user = get_object_or_404(User, pk=user_id, is_superuser=False)
    profile, _ = UserProfile.objects.get_or_create(user=user)

    if not profile.email_verified:
        messages.warning(request, "Cet utilisateur doit d’abord vérifier son email.")
        return redirect("admin_console")

    if profile.admin_approved:
        messages.info(request, "Ce compte est déjà validé.")
        return redirect("admin_console")

    if profile.admin_disabled:
        messages.warning(request, "Ce compte est désactivé. Réactivez-le avant de le valider.")
        return redirect("admin_console")

    profile.admin_approved = True
    profile.approved_at = timezone.now()
    profile.approved_by = request.user
    profile.save(update_fields=["admin_approved", "approved_at", "approved_by"])
    sync_user_activation_state(user, profile=profile)

    try:
        send_account_approved_email(user)
        messages.success(request, f"Le compte {user.username} a été validé et un email a été envoyé.")
    except Exception as exc:
        messages.warning(request, f"Le compte {user.username} a été validé, mais le mail n’a pas pu être envoyé : {exc}")

    return redirect("admin_console")


@superadmin_required
def toggle_user_active_view(request, user_id):
    """Bascule l'état actif/désactivé d'un compte sans supprimer ses données.

    Si le compte est désactivé, termine toutes ses sessions actives.
    Le super administrateur ne peut pas désactiver son propre compte.
    """
    if request.method != "POST":
        return redirect("admin_console")

    user = get_object_or_404(User, pk=user_id, is_superuser=False)

    if user == request.user:
        messages.error(request, "Le super administrateur ne peut pas désactiver son propre compte.")
        return redirect("admin_console")

    profile, _ = UserProfile.objects.get_or_create(user=user)

    if profile.admin_disabled:
        profile.admin_disabled = False
        profile.disabled_at = None
        profile.disabled_by = None
        profile.save(update_fields=["admin_disabled", "disabled_at", "disabled_by"])
        sync_user_activation_state(user, profile=profile)
        messages.success(request, f"Le compte {user.username} a été réactivé.")
        return redirect("admin_console")

    profile.admin_disabled = True
    profile.disabled_at = timezone.now()
    profile.disabled_by = request.user
    profile.save(update_fields=["admin_disabled", "disabled_at", "disabled_by"])
    sync_user_activation_state(user, profile=profile)
    purge_user_sessions(user)
    messages.success(request, f"Le compte {user.username} a été désactivé sans suppression des données.")
    return redirect("admin_console")


@superadmin_required
def unban_ip_view(request, ban_id):
    """Retire le bannissement d'une adresse IP."""
    if request.method != "POST":
        return redirect("admin_console")

    banned_ip = get_object_or_404(BannedIP, pk=ban_id)
    ip_address = banned_ip.ip_address
    banned_ip.delete()
    messages.success(request, f"L’adresse IP {ip_address} a été débannie.")
    return redirect("admin_console")


@login_required
def vulnerability_search_view(request):
    """Affiche et traite la recherche manuelle de vulnerabilites CVE via les APIs externes."""
    if request.method == "POST":
        selected_mode = request.POST.get("search_mode", "cpe") if request.method == "POST" else "cpe"       
    else:
        selected_mode = request.GET.get("search_mode", "cpe")

    form_values = {
        "cpe_name": "",
        "produit": "",
        "version": "",
        "vendor": "",
        "service": "",
        "package_name": "",
        "ecosystem": "",
    }

    selected_apis = []
    results_sections = []
    global_errors = []

    if request.method == "POST":
        for key in form_values.keys():
            form_values[key] = request.POST.get(key, "").strip()

        selected_apis = request.POST.getlist("apis")

        search_response = manual_vulnerability_search(
            mode=selected_mode,
            selected_apis=selected_apis,
            payload=form_values,
        )

        raw_results_by_api = search_response["results_by_api"]
        raw_errors_by_api = search_response["errors_by_api"]
        global_errors = search_response["global_errors"]

        for api in selected_apis:
            results_sections.append({
                "api_name": api,
                "results": raw_results_by_api.get(api, []),
                "error": raw_errors_by_api.get(api),
            })

    context = {
        "mode_config": SEARCH_MODE_CONFIG,
        "field_labels": FIELD_LABELS,
        "selected_mode": selected_mode,
        "selected_apis": selected_apis,
        "form_values": form_values,
        "results_sections": results_sections,
        "global_errors": global_errors,
        "mode_config_json": SEARCH_MODE_CONFIG,
    }

    return render(
        request,
        "app_dashboard/vulnerability_search_page.html",
        context,
    )
