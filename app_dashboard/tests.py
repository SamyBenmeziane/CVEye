from django.contrib.auth.models import User
from django.test import TestCase

from app_core.models import Cible, Scan, Service
from app_dashboard.risk_utils import (
    compute_severity_counts_risk_label,
    compute_vulnerability_count_risk_label,
    normalize_severity_label,
)
from app_dashboard.reporting import (
    build_target_report_filename,
    sanitize_filename,
)
from app_dashboard.views import (
    build_empty_severity_counts,
    build_machine_vulnerabilities_context,
    get_server_header,
)
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


class SanitizeFilenameTest(TestCase):
    """Tests pour la fonction sanitize_filename utilisee dans les rapports PDF."""

    def test_remplace_les_caracteres_speciaux(self):
        """sanitize_filename doit remplacer les caracteres non-alphanumeriques par des tirets"""
        self.assertEqual(sanitize_filename("192.168.1.1"), "192.168.1.1")
        self.assertEqual(sanitize_filename("exemple.fr"), "exemple.fr")
        self.assertEqual(sanitize_filename("mon serveur"), "mon-serveur")

    def test_supprime_les_tirets_de_bord(self):
        """sanitize_filename doit retirer les tirets en debut et fin"""
        self.assertEqual(sanitize_filename("/path/to/x/"), "path-to-x")

    def test_valeur_vide_donne_machine(self):
        """sanitize_filename sur une valeur vide doit retourner 'machine'"""
        self.assertEqual(sanitize_filename(""), "machine")
        self.assertEqual(sanitize_filename(None), "machine")


class BuildTargetReportFilenameTest(TestCase):
    """Tests pour la generation du nom de fichier des rapports PDF."""

    def setUp(self):
        self.user = User.objects.create_user(username="rep_user", password="x")
        self.target = Cible.objects.create(owner=self.user, adresse="192.168.1.10")

    def test_un_seul_scan_donne_dernier_scan(self):
        """Pour 1 scan, le suffixe doit etre 'dernier-scan'"""
        nom = build_target_report_filename(self.target, 1)
        self.assertEqual(nom, "rapport-192.168.1.10-dernier-scan.pdf")

    def test_plusieurs_scans_donne_un_pluriel(self):
        """Pour N scans, le suffixe doit indiquer le nombre"""
        nom = build_target_report_filename(self.target, 3)
        self.assertEqual(nom, "rapport-192.168.1.10-3-derniers-scans.pdf")


class GetServerHeaderTest(TestCase):
    """Tests pour la lecture insensible a la casse de l'en-tete Server."""

    def test_trouve_le_header_server(self):
        """get_server_header doit retourner la valeur de l'en-tete 'server'"""
        headers = {"Server": "Apache/2.4.41", "Content-Type": "text/html"}
        self.assertEqual(get_server_header(headers), "Apache/2.4.41")

    def test_insensible_a_la_casse(self):
        """get_server_header doit fonctionner avec n'importe quelle casse"""
        self.assertEqual(get_server_header({"SERVER": "nginx"}), "nginx")
        self.assertEqual(get_server_header({"server": "nginx"}), "nginx")

    def test_retourne_none_si_absent(self):
        """get_server_header doit retourner None si l'en-tete n'existe pas"""
        self.assertIsNone(get_server_header({"Content-Type": "text/html"}))
        self.assertIsNone(get_server_header({}))

    def test_retourne_none_si_pas_un_dict(self):
        """get_server_header doit retourner None si l'argument n'est pas un dict"""
        self.assertIsNone(get_server_header(None))
        self.assertIsNone(get_server_header("string"))


class BuildEmptySeverityCountsTest(TestCase):
    """Tests pour le helper qui initialise les compteurs de severite a zero."""

    def test_initialise_toutes_les_severites_a_zero(self):
        """build_empty_severity_counts doit creer un dict avec toutes les severites a 0"""
        counts = build_empty_severity_counts()

        self.assertEqual(counts["Critique"], 0)
        self.assertEqual(counts["Élevée"], 0)
        self.assertEqual(counts["Moyenne"], 0)
        self.assertEqual(counts["Faible"], 0)
        self.assertEqual(counts["Inconnue"], 0)
