import requests
from urllib.parse import quote


class CIRCLClient:
    BASE_URL = "https://vulnerability.circl.lu/api"

    def search_by_cpe(self, cpe):
        """
        Recherche les CVE associes a un CPE 2.3.
        Endpoint correct : /api/cve/cpe/{cpe_encode}
        (l'ancien /cpesearch/ retournait 404 sur les CPE 2.3)
        """
        if not cpe:
            return {"data": []}

        encoded_cpe = quote(cpe, safe="")
        url = f"{self.BASE_URL}/cve/cpe/{encoded_cpe}"

        try:
            response = requests.get(url, timeout=20)
        except requests.RequestException:
            return {"data": []}

        if response.status_code in (404, 422):
            return {"data": []}

        response.raise_for_status()

        raw = response.json()

        # L'API CIRCL peut retourner une liste directe ou un dict {"data": [...]}
        if isinstance(raw, list):
            return {"data": raw}
        return raw

    def search_by_vendor_product(self, vendor, product):
        """
        Recherche par vendeur + produit.
        Endpoint : /api/search/{vendor}/{product}
        """
        if not vendor or not product:
            return {"data": []}

        encoded_vendor = quote(vendor.lower(), safe="")
        encoded_product = quote(product.lower(), safe="")
        url = f"{self.BASE_URL}/search/{encoded_vendor}/{encoded_product}"

        try:
            response = requests.get(url, timeout=20)
        except requests.RequestException:
            return {"data": []}

        if response.status_code in (404, 422):
            return {"data": []}

        response.raise_for_status()

        raw = response.json()

        if isinstance(raw, list):
            return {"data": raw}
        return raw
