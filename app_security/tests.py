from django.test import TestCase

from app_security.services.nvd_client import NVDClient


class IsUsefulMatchStringTest(TestCase):

    def setUp(self):
        self.client = NVDClient()

    def test_cpe_avec_vendor_et_produit_est_utile(self):
        """Un CPE qui specifie vendor + produit + version doit etre considere utile"""
        cpe = "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
        self.assertTrue(self.client.is_useful_match_string(cpe))

    def test_cpe_que_des_wildcards_est_inutile(self):
        """Un CPE avec uniquement des wildcards (*) ne sert a rien et doit etre rejete"""
        cpe = "cpe:2.3:*:*:*:*:*:*:*:*:*:*:*"
        self.assertFalse(self.client.is_useful_match_string(cpe))

    def test_chaine_vide_ou_none_est_inutile(self):
        """Une chaine vide ou None doit etre rejetee proprement"""
        self.assertFalse(self.client.is_useful_match_string(""))
        self.assertFalse(self.client.is_useful_match_string(None))

    def test_chaine_trop_courte_est_inutile(self):
        """Une chaine qui n'a pas assez de parties doit etre rejetee"""
        self.assertFalse(self.client.is_useful_match_string("cpe:2.3"))


class ExtractCvesTest(TestCase):

    def setUp(self):
        self.client = NVDClient()

    def test_extrait_cve_id_severite_et_score(self):
        """extract_cves doit transformer une reponse NVD typique en dict utilisable"""
        fake_response = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-12345",
                        "published": "2024-01-15T10:00:00",
                        "descriptions": [
                            {"lang": "en", "value": "Remote code execution in Foo"},
                            {"lang": "fr", "value": "Execution de code distant dans Foo"},
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseSeverity": "CRITICAL", "baseScore": 9.8}}
                            ]
                        },
                    }
                }
            ]
        }

        results = self.client.extract_cves(fake_response)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["cve_id"], "CVE-2024-12345")
        self.assertEqual(results[0]["severity"], "CRITICAL")
        self.assertEqual(results[0]["score"], 9.8)
        self.assertEqual(results[0]["description"], "Remote code execution in Foo")

    def test_reponse_vide_ou_none(self):
        """extract_cves doit retourner une liste vide pour None ou un dict vide"""
        self.assertEqual(self.client.extract_cves(None), [])
        self.assertEqual(self.client.extract_cves({}), [])
        self.assertEqual(self.client.extract_cves({"vulnerabilities": []}), [])
