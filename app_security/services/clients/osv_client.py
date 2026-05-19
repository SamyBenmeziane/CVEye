import requests


class OSVClient:
    """Client HTTP pour lAPI OSV (Open Source Vulnerabilities)."""

    BASE_URL = "https://api.osv.dev/v1/query"

    def search(self, package_name, ecosystem, version):
        """Recherche les vulnerabilites d'un paquet dans un ecosysteme pour une version donnee."""
        if not package_name or not ecosystem or not version:
            return None

        payload = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem
            },
            "version": version
        }

        response = requests.post(self.BASE_URL, json=payload, timeout=5)
        response.raise_for_status()
        return response.json()