from app_security.services.clients.nvd_client import NVDClient
from app_security.services.clients.vulners_client import VulnersClient
from app_security.services.clients.circl_client import CIRCLClient
from app_security.services.clients.osv_client import OSVClient

from app_security.services.normalizer import (
    normalize_nvd,
    normalize_vulners,
    normalize_vulners_software_audit,
    normalize_circl,
    normalize_osv,
)


SEARCH_MODE_CONFIG = {
    "cpe": {
        "label": "Mode CPE",
        "apis": ["nvd", "vulners", "circl"],
        "fields": ["cpe_name"],
    },
    "service": {
        "label": "Mode Service",
        "apis": ["nvd", "vulners", "circl"],
        "fields": ["produit", "version", "vendor"],
    },
    "package": {
        "label": "Mode Package (OSV)",
        "apis": ["osv"],
        "fields": ["package_name", "ecosystem", "version"],
    },
}


FIELD_LABELS = {
    "cpe_name": "CPE name",
    "produit": "Produit",
    "version": "Version",
    "vendor": "Vendor / Fabricant (optionnel)",
    "package_name": "Package name",
    "ecosystem": "Ecosystem",
}


def deduplicate_results(results):
    """Deduplique une liste de vulnerabilites par couple source_api et cve_id."""
    unique = {}
    for item in results:
        key = (
            item.get("source_api"),
            item.get("cve_id"),
        )
        unique[key] = item
    return list(unique.values())


def validate_search_payload(mode, payload, selected_apis):
    """Verifie que les parametres de recherche sont complets et coherents avec le mode."""
    errors = []

    if mode not in SEARCH_MODE_CONFIG:
        errors.append("Mode de recherche invalide.")
        return errors

    allowed_apis = set(SEARCH_MODE_CONFIG[mode]["apis"])

    if not selected_apis:
        errors.append("Veuillez selectionner au moins une API.")

    for api in selected_apis:
        if api not in allowed_apis:
            errors.append(f"L'API '{api}' n'est pas compatible avec le mode '{mode}'.")

    if mode == "cpe":
        if not payload.get("cpe_name"):
            errors.append("Le champ cpe_name est obligatoire.")

    elif mode == "service":
        if not payload.get("produit"):
            errors.append("Le champ produit est obligatoire.")
        if not payload.get("version"):
            errors.append("Le champ version est obligatoire.")

    elif mode == "package":
        if not payload.get("package_name"):
            errors.append("Le champ package_name est obligatoire.")
        if not payload.get("ecosystem"):
            errors.append("Le champ ecosystem est obligatoire.")
        if not payload.get("version"):
            errors.append("Le champ version est obligatoire.")

    return errors


def search_nvd(mode, payload):
    """Interroge lAPI NVD selon le mode de recherche et retourne les resultats normalises."""
    client = NVDClient()

    if mode == "cpe":
        cpe_name = payload.get("cpe_name")
        data = client.search_cves(cpe_name)
        return normalize_nvd(
            data,
            {
                "query_value": cpe_name,
                "correlation_type": "cpe_name",
            },
        )

    if mode == "service":
        produit = payload.get("produit", "").strip()
        version = payload.get("version", "").strip()

        produit = produit.replace("_", " ")
        keyword = f"{payload.get('vendor', '')} {produit} {version}".strip()
        data = client.search_keyword(keyword)
        return normalize_nvd(
            data,
            {
                "query_value": keyword,
                "correlation_type": "keyword_search",
            },
        )

    return []


def search_vulners(mode, payload):
    """Interroge Vulners via software_audit et retourne les resultats normalises."""
    client = VulnersClient()

    if mode == "cpe":
        cpe_name = payload.get("cpe_name")
        # En mode CPE, on utilise software_audit avec type='cpe'
        data = client.software_audit(
            software=cpe_name,
            version="0",
            audit_type="cpe",
        )
        return normalize_vulners_software_audit(data, cpe_name)

    if mode == "service":
        produit = payload.get("produit", "").strip()
        version = payload.get("version", "").strip()

        data = client.software_audit(
            software=produit,
            version=version,
            audit_type="software",
            max_vulnerabilities=100,
        )
        return normalize_vulners_software_audit(data, f"{produit}:{version}")

    return []


def search_circl(mode, payload):
    """Interroge lAPI CIRCL par CPE ou par vendeur/produit et retourne les resultats normalises."""
    client = CIRCLClient()

    if mode == "cpe":
        cpe_name = payload.get("cpe_name", "").strip()

        data = client.search_by_cpe(cpe_name)
        results = normalize_circl(data)

        if results:
            return results

        parts = cpe_name.split(":")
        if len(parts) >= 5:
            vendor = parts[3]
            product = parts[4]
            data = client.search_by_vendor_product(vendor, product)
            return normalize_circl(data)

        return []

    if mode == "service":
        produit = payload.get("produit", "").strip()
        vendor = payload.get("vendor", "").strip() or produit

        data = client.search_by_vendor_product(vendor, produit)
        return normalize_circl(data)

    return []

def search_osv(mode, payload):
    """Interroge lAPI OSV uniquement en mode package et retourne les resultats normalises."""
    if mode != "package":
        return []

    client = OSVClient()
    package_name = payload.get("package_name", "").strip()
    ecosystem = payload.get("ecosystem", "").strip()
    version = payload.get("version", "").strip()

    data = client.search(package_name, ecosystem, version)
    return normalize_osv(data, package_name, ecosystem, version)


API_DISPATCH = {
    "nvd": search_nvd,
    "vulners": search_vulners,
    "circl": search_circl,
    "osv": search_osv,
}


def manual_vulnerability_search(mode, selected_apis, payload):
    """Lance la recherche manuelle de vulnerabilites sur les APIs selectionnees et agregge les resultats."""
    global_errors = validate_search_payload(mode, payload, selected_apis)

    results_by_api = {api: [] for api in selected_apis}
    errors_by_api = {}

    if global_errors:
        return {
            "results_by_api": results_by_api,
            "errors_by_api": errors_by_api,
            "global_errors": global_errors,
        }

    for api in selected_apis:
        try:
            raw_results = API_DISPATCH[api](mode, payload)
            results_by_api[api] = deduplicate_results(raw_results)
        except Exception as exc:
            errors_by_api[api] = str(exc)
            results_by_api[api] = []

    return {
        "results_by_api": results_by_api,
        "errors_by_api": errors_by_api,
        "global_errors": [],
    }
