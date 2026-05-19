import requests
import time

from django.conf import settings


class NVDClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    REQUEST_TIMEOUT_SECONDS = getattr(settings, "NVD_REQUEST_TIMEOUT_SECONDS", 2)
    MAX_RETRIES = getattr(settings, "NVD_MAX_RETRIES", 2)
    BACKOFF_SECONDS = getattr(settings, "NVD_BACKOFF_SECONDS", 0.2)

    def is_useful_match_string(self, cpe_match_string):
        """Dit si la chaine CPE est assez precise pour servir"""
        if not cpe_match_string:
            return False

        parts = cpe_match_string.split(":")
        if len(parts) < 6:
            return False

        cpe_part = parts[2]
        vendor = parts[3]
        product = parts[4]
        version = parts[5]

        useful_fields = [cpe_part, vendor, product, version]
        return any(value not in ["*", "", None] for value in useful_fields)

    def choose_cpe_for_lookup(self, service):
        """Choisit la meilleure valeur CPE pour chercher les CVE"""
        if service.cpe_name:
            return {
                "correlation_type": "exact",
                "query_value": service.cpe_name,
            }

        if self.is_useful_match_string(service.cpe_match_string):
            return {
                "correlation_type": "approximate",
                "query_value": service.cpe_match_string,
            }

        return {
            "correlation_type": "none",
            "query_value": None,
        }

    def search_cves(self, query_value, results_per_page=5):
        """Interroge lAPI NVD pour recuperer les CVE"""
        if not query_value:
            return None

        params = {
            "cpeName": query_value,
            "resultsPerPage": results_per_page,
        }

        last_error = None

        for attempt in range(self.MAX_RETRIES):
            try:
                response = requests.get(
                    self.BASE_URL,
                    params=params,
                    timeout=self.REQUEST_TIMEOUT_SECONDS,
                    headers={"User-Agent": "CVEye/1.0"},
                )
                response.raise_for_status()
                return response.json()
            except requests.RequestException as error:
                last_error = error
                if attempt < self.MAX_RETRIES - 1:
                    time.sleep(self.BACKOFF_SECONDS * (attempt + 1))

        raise last_error

    def extract_cves(self, data):
        """Extrait les infos utiles depuis la reponse NVD"""
        results = []
        if not data:
            return results

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})

            cve_id = cve.get("id")
            published = cve.get("published")

            description = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            severity = None
            score = None
            metrics = cve.get("metrics", {})

            # On prend la meilleure version CVSS dispo en priorite
            if metrics.get("cvssMetricV31"):
                metric = metrics["cvssMetricV31"][0]
                severity = metric.get("cvssData", {}).get("baseSeverity")
                score = metric.get("cvssData", {}).get("baseScore")
            elif metrics.get("cvssMetricV30"):
                metric = metrics["cvssMetricV30"][0]
                severity = metric.get("cvssData", {}).get("baseSeverity")
                score = metric.get("cvssData", {}).get("baseScore")
            elif metrics.get("cvssMetricV2"):
                metric = metrics["cvssMetricV2"][0]
                severity = metric.get("baseSeverity")
                score = metric.get("cvssData", {}).get("baseScore")

            results.append(
                {
                    "cve_id": cve_id,
                    "published": published,
                    "description": description,
                    "severity": severity,
                    "score": score,
                }
            )

        return results

    def lookup_service_vulnerabilities(self, service):
        """Cherche les vulnerabilites pour un service donne"""
        choice = self.choose_cpe_for_lookup(service)

        if not choice["query_value"]:
            return {
                "correlation_type": choice["correlation_type"],
                "query_value": None,
                "vulnerabilities": [],
            }

        data = self.search_cves(choice["query_value"])
        vulnerabilities = self.extract_cves(data)

        return {
            "correlation_type": choice["correlation_type"],
            "query_value": choice["query_value"],
            "vulnerabilities": vulnerabilities,
        }
