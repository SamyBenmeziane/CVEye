from django.contrib.auth.models import User
from django.test import TestCase

from app_core.models import Cible, Scan, Service
from app_dashboard.risk_utils import (
    compute_severity_counts_risk_label,
    compute_vulnerability_count_risk_label,
    normalize_severity_label,
)
from app_dashboard.views import build_machine_vulnerabilities_context
from app_security.models import Vulnerability


class NormalizeSeverityLabelTest(TestCase):

    def test_mappe_severites_anglaises_vers_francais(self):
        """normalize_severity_label doit traduire les niveaux anglais des API CVE en libelles francais"""
        self.assertEqual(normalize_severity_label("CRITICAL"), "Critique")
        self.assertEqual(normalize_severity_label("HIGH"), "Élevée")
        self.assertEqual(normalize_severity_label("MEDIUM"), "Moyenne")
        self.assertEqual(normalize_severity_label("LOW"), "Faible")
        self.assertEqual(normalize_severity_label("inconnu_xyz"), "Inconnue")


class ComputeVulnerabilityCountRiskLabelTest(TestCase):

    def test_seuils_de_risque(self):
        """Le niveau de risque doit suivre les seuils : 0=Faible, 1-2=Moyen, 3-4=Eleve, 5+=Critique"""
        self.assertEqual(compute_vulnerability_count_risk_label(0), "Faible")
        self.assertEqual(compute_vulnerability_count_risk_label(1), "Moyen")
        self.assertEqual(compute_vulnerability_count_risk_label(2), "Moyen")
        self.assertEqual(compute_vulnerability_count_risk_label(3), "Élevé")
        self.assertEqual(compute_vulnerability_count_risk_label(4), "Élevé")
        self.assertEqual(compute_vulnerability_count_risk_label(5), "Critique")
        self.assertEqual(compute_vulnerability_count_risk_label(50), "Critique")


class ComputeSeverityCountsRiskLabelTest(TestCase):

    def test_priorise_les_severites_hautes(self):
        """Doit retourner Critique des qu'il y a >=1 critique, meme avec d'autres severites"""
        # 1 Critique meme avec 100 Faibles -> Critique
        counts = {"Critique": 1, "Élevée": 0, "Moyenne": 0, "Faible": 100, "Inconnue": 0}
        self.assertEqual(compute_severity_counts_risk_label(counts), "Critique")

        # 0 Critique mais 1 Elevee -> Eleve
        counts = {"Critique": 0, "Élevée": 1, "Moyenne": 5, "Faible": 5, "Inconnue": 0}
        self.assertEqual(compute_severity_counts_risk_label(counts), "Élevé")

        # Que des Moyennes -> Moyen
        counts = {"Critique": 0, "Élevée": 0, "Moyenne": 3, "Faible": 0, "Inconnue": 0}
        self.assertEqual(compute_severity_counts_risk_label(counts), "Moyen")

        # Aucune severite -> Faible
        counts = {"Critique": 0, "Élevée": 0, "Moyenne": 0, "Faible": 0, "Inconnue": 0}
        self.assertEqual(compute_severity_counts_risk_label(counts), "Faible")


class BuildMachineVulnerabilitiesContextTest(TestCase):
    """Verifie le tri 3-buckets : Critique > Vuln non-critique > Sans vuln"""

    def setUp(self):
        self.user = User.objects.create_user(username="bucket_test", password="x")

        # Cible 1 : avec une CVE Critique
        self.cible_critique = Cible.objects.create(owner=self.user, adresse="10.10.0.1")
        scan1 = Scan.objects.create(cible=self.cible_critique, owner=self.user, statut="complete")
        srv1 = Service.objects.create(scan=scan1, port=22, nom_service="ssh")
        Vulnerability.objects.create(service=srv1, cve_id="CVE-2024-AAA", severity="CRITICAL", score=9.8)

        # Cible 2 : avec une CVE non-critique (Faible)
        self.cible_faible = Cible.objects.create(owner=self.user, adresse="10.10.0.2")
        scan2 = Scan.objects.create(cible=self.cible_faible, owner=self.user, statut="complete")
        srv2 = Service.objects.create(scan=scan2, port=80, nom_service="http")
        Vulnerability.objects.create(service=srv2, cve_id="CVE-2024-BBB", severity="LOW", score=2.5)

        # Cible 3 : sans aucune CVE
        self.cible_propre = Cible.objects.create(owner=self.user, adresse="10.10.0.3")
        Scan.objects.create(cible=self.cible_propre, owner=self.user, statut="complete")

    def test_ordre_critique_puis_non_critique_puis_sans_vuln(self):
        ctx = build_machine_vulnerabilities_context(self.user)
        ordre = [row["target"].adresse for row in ctx["machine_rows"]]

        self.assertEqual(ordre, ["10.10.0.1", "10.10.0.2", "10.10.0.3"])

    def test_filtre_exposed_only_cache_les_machines_sans_cve(self):
        """Avec exposed_only=True, seules les machines ayant >=1 CVE doivent rester"""
        ctx = build_machine_vulnerabilities_context(self.user, exposed_only=True)
        adresses = [row["target"].adresse for row in ctx["machine_rows"]]

        # 10.10.0.3 est sans CVE -> doit etre absente
        self.assertNotIn("10.10.0.3", adresses)
        # Les 2 autres doivent etre presentes
        self.assertIn("10.10.0.1", adresses)
        self.assertIn("10.10.0.2", adresses)
        self.assertEqual(len(adresses), 2)
