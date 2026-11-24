from django.test import TestCase

from app_security.services.nvd_client import NVDClient
from app_security.services.normalizer import (
    normalize_nvd,
    normalize_circl,
    normalize_osv,
    normalize_vulners_software_audit,
)
from app_security.services.manual_search import (
    validate_search_payload,
    deduplicate_results,
)


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


class NormalizeNvdTest(TestCase):
    """Tests pour la normalisation des reponses NVD vers le format interne."""

    def test_extrait_les_champs_principaux(self):
        """normalize_nvd doit extraire cve_id, severity, score et description"""
        data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-0001",
                        "published": "2024-01-15T10:00:00",
                        "descriptions": [
                            {"lang": "en", "value": "Test vulnerability"},
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseSeverity": "HIGH", "baseScore": 7.5}}
                            ]
                        },
                    }
                }
            ]
        }
        results = normalize_nvd(data, {"query_value": "cpe:test", "correlation_type": "cpe_name"})

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["cve_id"], "CVE-2024-0001")
        self.assertEqual(results[0]["severity"], "HIGH")
        self.assertEqual(results[0]["score"], 7.5)
        self.assertEqual(results[0]["source_api"], "nvd")

    def test_donnees_vides_retournent_liste_vide(self):
        """normalize_nvd doit gerer None et dict vide proprement"""
        self.assertEqual(normalize_nvd(None, {"query_value": "", "correlation_type": ""}), [])
        self.assertEqual(normalize_nvd({}, {"query_value": "", "correlation_type": ""}), [])


class NormalizeCirclTest(TestCase):
    """Tests pour la normalisation des reponses CIRCL."""

    def test_format_liste_directe(self):
        """normalize_circl doit gerer une liste directe d'objets"""
        data = [
            {
                "id": "CVE-2024-9999",
                "summary": "Description CIRCL",
                "cvss": 8.0,
                "severity": "HIGH",
            }
        ]
        results = normalize_circl(data)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["cve_id"], "CVE-2024-9999")
        self.assertEqual(results[0]["source_api"], "circl")

    def test_format_dict_avec_cle_data(self):
        """normalize_circl doit gerer un dict avec la cle 'data'"""
        data = {"data": [{"id": "CVE-2024-8888", "summary": "test"}]}
        results = normalize_circl(data)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["cve_id"], "CVE-2024-8888")

    def test_donnees_vides(self):
        """normalize_circl doit retourner une liste vide pour None ou dict vide"""
        self.assertEqual(normalize_circl(None), [])
        self.assertEqual(normalize_circl({}), [])
        self.assertEqual(normalize_circl({"data": []}), [])


class NormalizeOsvTest(TestCase):
    """Tests pour la normalisation des reponses OSV."""

    def test_extrait_les_vulnerabilites(self):
        """normalize_osv doit extraire id et summary depuis vulns"""
        data = {
            "vulns": [
                {"id": "GHSA-1234", "summary": "Buffer overflow", "published": "2024-01-01"},
            ]
        }
        results = normalize_osv(data, "django", "PyPI", "3.0")

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["cve_id"], "GHSA-1234")
        self.assertEqual(results[0]["source_api"], "osv")
        self.assertEqual(results[0]["query_value"], "django:PyPI:3.0")

    def test_donnees_vides(self):
        """normalize_osv doit retourner une liste vide pour None"""
        self.assertEqual(normalize_osv(None, "pkg", "PyPI", "1.0"), [])
        self.assertEqual(normalize_osv({}, "pkg", "PyPI", "1.0"), [])


class NormalizeVulnersTest(TestCase):
    """Tests pour la normalisation des reponses Vulners software_audit."""

    def test_extrait_les_entrees_avec_id_cve(self):
        """normalize_vulners_software_audit doit garder les entrees dont l'id est une CVE"""
        data = {
            "data": {
                "search": [
                    {
                        "id": "CVE-2024-5555",
                        "title": "RCE in foo",
                        "description": "Description detaillee",
                        "cvss": {"score": 9.0, "severity": "CRITICAL"},
                    }
                ]
            }
        }
        results = normalize_vulners_software_audit(data, "foo:1.0")

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["cve_id"], "CVE-2024-5555")
        self.assertEqual(results[0]["source_api"], "vulners")
        self.assertEqual(results[0]["score"], 9.0)
        self.assertEqual(results[0]["severity"], "CRITICAL")

    def test_ignore_les_id_non_cve(self):
        """Les entrees dont l'id n'est pas une CVE doivent etre ignorees"""
        data = {
            "data": {
                "search": [
                    {"id": "BUGTRAQ:9999", "title": "Bugtraq advisory"},
                ]
            }
        }
        self.assertEqual(normalize_vulners_software_audit(data, "x"), [])

    def test_donnees_vides(self):
        """normalize_vulners_software_audit doit gerer None et dict vide"""
        self.assertEqual(normalize_vulners_software_audit(None, "x"), [])
        self.assertEqual(normalize_vulners_software_audit({}, "x"), [])


class ValidateSearchPayloadTest(TestCase):
    """Tests pour la validation des payloads de recherche manuelle."""

    def test_mode_invalide(self):
        """Un mode inconnu doit produire une erreur"""
        errors = validate_search_payload("inconnu", {}, ["nvd"])
        self.assertTrue(any("Mode" in e for e in errors))

    def test_mode_cpe_sans_cpe_name(self):
        """En mode cpe, l'absence de cpe_name doit produire une erreur"""
        errors = validate_search_payload("cpe", {}, ["nvd"])
        self.assertTrue(any("cpe_name" in e for e in errors))

    def test_mode_service_sans_produit_ni_version(self):
        """En mode service, produit et version sont obligatoires"""
        errors = validate_search_payload("service", {}, ["nvd"])
        self.assertTrue(any("produit" in e for e in errors))
        self.assertTrue(any("version" in e for e in errors))

    def test_mode_package_sans_ecosystem(self):
        """En mode package, ecosystem est obligatoire"""
        errors = validate_search_payload(
            "package",
            {"package_name": "django", "version": "3.0"},
            ["osv"],
        )
        self.assertTrue(any("ecosystem" in e for e in errors))

    def test_api_incompatible_avec_le_mode(self):
        """Une API non autorisee pour le mode doit produire une erreur"""
        errors = validate_search_payload(
            "package",
            {"package_name": "django", "ecosystem": "PyPI", "version": "3.0"},
            ["nvd"],
        )
        self.assertTrue(any("nvd" in e for e in errors))

    def test_payload_valide_en_mode_cpe(self):
        """Un payload bien forme ne doit produire aucune erreur"""
        errors = validate_search_payload(
            "cpe",
            {"cpe_name": "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"},
            ["nvd"],
        )
        self.assertEqual(errors, [])

    def test_aucune_api_selectionnee(self):
        """Une recherche sans API selectionnee doit produire une erreur"""
        errors = validate_search_payload("cpe", {"cpe_name": "x"}, [])
        self.assertTrue(any("API" in e for e in errors))


class DeduplicateResultsTest(TestCase):
    """Tests pour la deduplication des resultats agreges."""

    def test_deduplique_par_source_et_cve(self):
        """deduplicate_results doit garder une seule entree par couple (source_api, cve_id)"""
        items = [
            {"source_api": "nvd", "cve_id": "CVE-2024-1", "description": "v1"},
            {"source_api": "nvd", "cve_id": "CVE-2024-1", "description": "v2"},
            {"source_api": "circl", "cve_id": "CVE-2024-1", "description": "v3"},
        ]
        results = deduplicate_results(items)

        # 2 entrees : (nvd, CVE-2024-1) et (circl, CVE-2024-1)
        self.assertEqual(len(results), 2)

    def test_liste_vide(self):
        """deduplicate_results sur liste vide doit retourner une liste vide"""
        self.assertEqual(deduplicate_results([]), [])
