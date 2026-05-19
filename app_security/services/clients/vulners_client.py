import os
import requests


class VulnersClient:
    SEARCH_URL = "https://vulners.com/api/v3/search/lucene/"
    SOFTWARE_API_URL = "https://vulners.com/api/v3/burp/softwareapi/"

    def __init__(self):
        self.api_key = os.getenv("VULNERS_API_KEY")

    def search_lucene(self, query):
        """
        Recherche via l'endpoint Lucene (plans payants uniquement).
        Leve une Exception explicite si l'API repond 402.
        """
        if not query or not self.api_key:
            return None

        headers = {
            "Content-Type": "application/json",
            "X-Api-Key": self.api_key,
        }

        payload = {
            "query": query,
            "skip": 0,
            "size": 100,
        }

        response = requests.post(
            self.SEARCH_URL,
            json=payload,
            headers=headers,
            timeout=15,
        )

        if response.status_code == 402:
            raise Exception(
                "Vulners 402 Payment Required : l'endpoint Lucene est "
                "reserve aux plans payants. Utilisez software_audit() a la place."
            )

        response.raise_for_status()
        return response.json()

    def software_audit(self, software, version, audit_type="software", max_vulnerabilities=100):
        """
        Recherche par nom de logiciel + version via l'endpoint gratuit.
        audit_type : 'software' (defaut) ou 'cpe'.
        """
        if not software or not version or not self.api_key:
            return None

        headers = {
            "Content-Type": "application/json",
            "X-Api-Key": self.api_key,
        }

        payload = {
            "software": software,
            "version": version,
            "type": audit_type,
            "maxVulnerabilities": max_vulnerabilities,
            "apiKey": self.api_key,
        }

        response = requests.post(
            self.SOFTWARE_API_URL,
            json=payload,
            headers=headers,
            timeout=20,
        )
        response.raise_for_status()
        return response.json()
