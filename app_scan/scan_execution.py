from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import socket

from django.conf import settings
from django.db import close_old_connections, connections
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from app_core.models import Scan, Service
from app_scan.progress import pop_scan_progress, set_scan_progress
from app_scan.scanner import SocketScanner
from app_scan.scheduler_utils import calculer_prochain_scan
from app_scan.serveur_hs import est_serveur_hs
from app_security.models import Vulnerability
from app_security.services.nvd_client import NVDClient

PROGRESS_DB_SYNC_INTERVAL = 250
DEFAULT_CVE_LOOKUP_MAX_THREADS = getattr(settings, "CVE_LOOKUP_MAX_THREADS", 8)


def resolve_target_address(target):
    """Résout l'adresse IP à scanner pour une cible (résolution DNS pour les domaines)."""
    if target.type_cible != "domaine":
        return target.adresse

    try:
        return socket.gethostbyname(target.adresse)
    except socket.gaierror as exc:
        raise ValueError(f"Resolution DNS impossible pour {target.adresse}: {exc}") from exc


def get_service_lookup_key(service_obj):
    """Génère une clé de regroupement pour éviter des appels NVD redondants sur des services identiques."""
    # Cette cle evite de refaire la meme recherche CVE pour plusieurs services identiques
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
    """Interroge l'API NVD et retourne la liste des vulnérabilités connues pour un service."""
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


def fetch_group_vulnerabilities(grouped_services, nvd_client):
    """Interroge l'API NVD en parallèle pour chaque groupe de services unique, sans accès ORM depuis les workers."""
    if not grouped_services:
        return {}

    results = {}
    max_workers = max(1, min(DEFAULT_CVE_LOOKUP_MAX_THREADS, len(grouped_services)))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_key = {
            executor.submit(
                lookup_vulnerabilities_for_service,
                services_group[0],
                nvd_client,
            ): lookup_key
            for lookup_key, services_group in grouped_services.items()
        }

        for future in as_completed(future_to_key):
            lookup_key = future_to_key[future]
            try:
                results[lookup_key] = future.result()
            except Exception:
                results[lookup_key] = []

    return results


def attach_vulnerabilities_to_service(service_obj, vulnerabilities):
    """Persiste les vulnérabilités trouvées en les associant au service via get_or_create."""
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


def build_scan_version_label(ports=None):
    """Construit l'étiquette de version du scanner, en encodant les ports ciblés si précisés."""
    if not ports:
        return "SocketScanner"

    normalized = sorted({int(port) for port in ports})
    return "SocketScanner[ports:" + ",".join(str(port) for port in normalized) + "]"


def extract_target_ports(scan_obj):
    """Extrait la liste des ports ciblés encodée dans le libellé version_scanner du scan.

    Retourne une liste d'entiers valides si des ports sont encodés, None sinon (scan complet).
    """
    version_label = (scan_obj.version_scanner or "").strip()
    match = re.search(r"\[ports:([0-9,]+)\]", version_label)
    if not match:
        return None

    ports = []
    for raw_port in match.group(1).split(","):
        try:
            port = int(raw_port)
        except (TypeError, ValueError):
            continue

        if 1 <= port <= SocketScanner.TOTAL_PORTS:
            ports.append(port)

    return ports or None


def create_scan_record(target, user, ports=None):
    """Crée et persiste un enregistrement de scan en base avec le statut initial 'en_cours'.

    Normalise et déduplique les ports fournis ; si la liste est vide, le scan couvre tous les ports.
    """
    normalized_ports = []
    for port in ports or []:
        try:
            port_int = int(port)
        except (TypeError, ValueError):
            continue

        if 1 <= port_int <= SocketScanner.TOTAL_PORTS and port_int not in normalized_ports:
            normalized_ports.append(port_int)

    normalized_ports.sort()
    total_ports = len(normalized_ports) if normalized_ports else SocketScanner.TOTAL_PORTS

    return Scan.objects.create(
        cible=target,
        owner=user,
        statut="en_cours",
        version_scanner=build_scan_version_label(normalized_ports),
        ports_scannes=total_ports,
        ports_scannes_courant=0,
        ports_ouverts=0,
    )


def execute_scan_for_target(target, user, scan_obj=None):
    """Orchestre l'exécution complète d'un scan pour une cible : résolution DNS, scan des ports,
    identification des services, corrélation CVE via NVD et planification du prochain scan périodique.

    Crée un enregistrement de scan si scan_obj n'est pas fourni. Met à jour la progression en temps
    réel dans Redis (via set_scan_progress) et en base à intervalles réguliers. En cas d'erreur,
    persiste l'état d'échec avec le message d'exception avant de fermer les connexions Django.
    Retourne un dict {'erreur': None|str, 'scan_obj': Scan}.
    """
    close_old_connections()
    scan_obj = scan_obj or create_scan_record(target, user)

    try:
        scan_address = resolve_target_address(target)
        target_ports = extract_target_ports(scan_obj)
        total_ports = len(target_ports) if target_ports else SocketScanner.TOTAL_PORTS

        # On remet le scan dans un etat propre au cas ou il soit relance
        Scan.objects.filter(pk=scan_obj.pk).update(
            statut="en_cours",
            date_fin=None,
            message_erreur="",
            version_scanner=build_scan_version_label(target_ports),
            ports_scannes=total_ports,
            ports_scannes_courant=0,
            ports_ouverts=0,
        )

        set_scan_progress(
            scan_obj.pk,
            status="en_cours",
            ports_scanned_current=0,
            ports_scanned_total=total_ports,
            ports_open=0,
            started_at=scan_obj.date_debut.isoformat() if scan_obj.date_debut else None,
            updated_at=timezone.now().isoformat(),
            target_address=target.adresse,
            error_message="",
        )

        # Cette fonction locale alimente le suivi en direct sans attendre la fin du scan
        def update_progress(scanned_ports, total_ports_count):
            """Met a jour lavancement pendant le scan"""
            open_ports_count = len(scanner.resultat) if "scanner" in locals() else 0
            set_scan_progress(
                scan_obj.pk,
                status="en_cours",
                ports_scanned_current=scanned_ports,
                ports_scanned_total=total_ports_count,
                ports_open=open_ports_count,
                updated_at=timezone.now().isoformat(),
            )

            if scanned_ports == total_ports_count or scanned_ports % PROGRESS_DB_SYNC_INTERVAL == 0:
                Scan.objects.filter(pk=scan_obj.pk).update(
                    ports_scannes=total_ports_count,
                    ports_scannes_courant=scanned_ports,
                    ports_ouverts=open_ports_count,
                )

        scanner = SocketScanner(
            scan_address,
            progress_callback=update_progress,
            ports=target_ports,
        )

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

        # On cree dabord tous les services puis on groupe ceux qui se ressemblent pour la recherche CVE
        grouped_services = defaultdict(list)
        for service_obj in created_services:
            lookup_key = get_service_lookup_key(service_obj)
            if lookup_key:
                grouped_services[lookup_key].append(service_obj)

        nvd_client = NVDClient()
        grouped_vulnerabilities = fetch_group_vulnerabilities(grouped_services, nvd_client)

        # Un seul resultat NVD par groupe puis on recopie les memes CVE aux services equivalents
        for lookup_key, services_group in grouped_services.items():
            vulnerabilities = grouped_vulnerabilities.get(lookup_key, [])
            if not vulnerabilities:
                continue

            for service_obj in services_group:
                attach_vulnerabilities_to_service(service_obj, vulnerabilities)

        # Meme si le scan ne plante pas on verifie si la machine semble totalement hors ligne
        completion_time = timezone.now()
        is_server_down = est_serveur_hs(scan_address, resultat_scan)

        Scan.objects.filter(pk=scan_obj.pk).update(
            statut="complete",
            date_fin=completion_time,
            ports_ouverts=ouverts,
            server_hs=is_server_down,
            ports_scannes_courant=total_ports,
        )

        scan_obj.statut = "complete"
        scan_obj.date_fin = completion_time
        scan_obj.ports_ouverts = ouverts
        scan_obj.server_hs = is_server_down
        scan_obj.ports_scannes_courant = total_ports
        pop_scan_progress(scan_obj.pk)

        if target.surveillance_active and target.periodicite_scan:
            maintenant = timezone.now()
            target.dernier_scan_le = maintenant
            target.prochain_scan_le = calculer_prochain_scan(maintenant, target.periodicite_scan)
            target.save(update_fields=["dernier_scan_le", "prochain_scan_le"])

        return {"erreur": None, "scan_obj": scan_obj}

    except Exception as exc:
        # En cas derreur on garde un etat le plus utile possible pour la page davancement
        failure_time = timezone.now()
        current_progress = scanner.scanned_ports if "scanner" in locals() else 0
        current_open_ports = len(scanner.resultat) if "scanner" in locals() else 0
        error_message = str(exc)

        Scan.objects.filter(pk=scan_obj.pk).update(
            statut="echoue",
            date_fin=failure_time,
            message_erreur=error_message,
            ports_scannes=total_ports if "total_ports" in locals() else SocketScanner.TOTAL_PORTS,
            ports_scannes_courant=current_progress,
            ports_ouverts=current_open_ports,
        )

        scan_obj.statut = "echoue"
        scan_obj.date_fin = failure_time
        scan_obj.message_erreur = error_message
        scan_obj.ports_scannes_courant = current_progress
        scan_obj.ports_ouverts = current_open_ports
        pop_scan_progress(scan_obj.pk)

        return {"erreur": f"Erreur pendant le scan : {exc}", "scan_obj": scan_obj}

    finally:
        connections.close_all()


def execute_scan_from_record(scan_id):
    """Recharge un scan existant depuis son identifiant et relance son exécution complète."""
    close_old_connections()
    try:
        scan_obj = Scan.objects.select_related("cible", "owner").get(pk=scan_id)
        return execute_scan_for_target(scan_obj.cible, scan_obj.owner, scan_obj=scan_obj)
    finally:
        connections.close_all()
