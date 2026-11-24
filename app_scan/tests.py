from datetime import datetime, timezone as dt_timezone
from django.test import TestCase
from unittest.mock import patch

from app_scan.scanner import SocketScanner
from app_scan.scheduler_utils import calculer_prochain_scan
from app_scan.progress import set_scan_progress, get_scan_progress, pop_scan_progress
from app_scan.scan_execution import (
    get_service_lookup_key,
    build_scan_version_label,
)
from app_core.models import Cible, Scan, Service
from django.contrib.auth.models import User
from unittest.mock import patch
class ScannerTest(TestCase):

    def test_sanitize_text_removes_null_characters(self):
        scanner = SocketScanner("127.0.0.1")

        dirty_text = "hello\x00world"
        clean_text = scanner.sanitize_text(dirty_text)

        self.assertEqual(clean_text, "helloworld")

    def test_sanitize_text_with_none(self):
        scanner = SocketScanner("127.0.0.1")

        result = scanner.sanitize_text(None)

        self.assertIsNone(result)

    def test_verif_port_open_calls_identifier_service(self):
        scanner = SocketScanner("127.0.0.1")

        with patch("socket.socket") as mock_socket:
            instance = mock_socket.return_value
            instance.connect_ex.return_value = 0  # port ouvert

            with patch.object(scanner, "identifier_service") as mock_identifier:
                scanner.verif_port(80)

                mock_identifier.assert_called_once_with(80)

    def test_parse_version_extrait_version_classique(self):
        """parse_version doit extraire correctement une version sur 2 ou 3 chiffres"""
        scanner = SocketScanner("127.0.0.1", ports=[80])

        self.assertEqual(scanner.parse_version("Apache/2.4.41"), "2.4.41")
        self.assertEqual(scanner.parse_version("OpenSSH 7.4"), "7.4")
        self.assertEqual(scanner.parse_version("nginx/1.18.0"), "1.18.0")
        self.assertEqual(scanner.parse_version("aucune version ici"), "???")

    def test_normalize_product_mappe_vers_format_cpe(self):
        """normalize_product doit traduire les noms vers les identifiants utilises par NIST"""
        scanner = SocketScanner("127.0.0.1", ports=[80])

        # Produits connus -> mapping specifique NIST
        self.assertEqual(scanner.normalize_product("Apache"), "http_server")
        self.assertEqual(scanner.normalize_product("OpenSSH"), "openssh")
        self.assertEqual(scanner.normalize_product("vsftpd"), "ftp")

        # Produit inconnu -> minuscules + espaces remplaces par underscores
        self.assertEqual(scanner.normalize_product("Microsoft Web Server"), "microsoft_web_server")

        # Cas vides
        self.assertEqual(scanner.normalize_product(""), "???")
        self.assertEqual(scanner.normalize_product("???"), "???")
        self.assertEqual(scanner.normalize_product(None), "???")

    def test_detect_vendor_identifie_les_editeurs_connus(self):
        """detect_vendor doit deviner l'editeur a partir du nom de produit"""
        scanner = SocketScanner("127.0.0.1", ports=[80])

        # Produits avec mapping connu
        self.assertEqual(scanner.detect_vendor("OpenSSH 8.0"), "openbsd")
        self.assertEqual(scanner.detect_vendor("Apache/2.4.41"), "apache")

        # Produit inconnu
        self.assertEqual(scanner.detect_vendor("MaSuperApp"), "???")

        # Cas vides
        self.assertEqual(scanner.detect_vendor(""), "???")
        self.assertEqual(scanner.detect_vendor("???"), "???")
        self.assertEqual(scanner.detect_vendor(None), "???")
                
class ScanExecutionTest(TestCase):

    def test_get_service_lookup_key_with_cpe_name(self):
        user = User.objects.create_user(
            username="scan_user",
            password="testpass123"
        )

        cible = Cible.objects.create(
            owner=user,
            adresse="127.0.0.1"
        )

        scan = Scan.objects.create(
            cible=cible,
            owner=user
        )

        service = Service.objects.create(
            scan=scan,
            port=80,
            protocole="tcp",
            nom_service="http",
            produit="Apache",
            version="2.4.49",
            cpe_name="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
        )

        result = get_service_lookup_key(service)

        self.assertEqual(
            result,
            "cpe_name::cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
        )
    
    def test_get_service_lookup_key_without_cpe(self):
        user = User.objects.create_user(
            username="scan_user2",
            password="testpass123"
        )

        cible = Cible.objects.create(
            owner=user,
            adresse="127.0.0.1"
        )

        scan = Scan.objects.create(
            cible=cible,
            owner=user
        )

        service = Service.objects.create(
            scan=scan,
            port=443,
            protocole="tcp",
            nom_service="https",
            produit="nginx",
            version="1.18.0",
            cpe_name=None
        )

        result = get_service_lookup_key(service)

        self.assertEqual(
            result,
            "service::https|nginx|1.18.0"
        ) 
        




class APITest(TestCase):

    @patch("requests.get")
    def test_nvd_api_mock(self, mock_get):
        mock_response = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-1234"
                    }
                }
            ]
        }

        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = mock_response

        import requests
        response = requests.get("https://fake-nvd-api")

        data = response.json()

        self.assertEqual(data["vulnerabilities"][0]["cve"]["id"], "CVE-2024-1234")
        
class CalculerProchainScanTest(TestCase):
    """Tests pour la planification des scans periodiques."""

    def setUp(self):
        self.date_base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt_timezone.utc)

    def test_periodicite_toutes_les_heures(self):
        """toutes_les_heures doit ajouter exactement 1 heure"""
        resultat = calculer_prochain_scan(self.date_base, "toutes_les_heures")
        self.assertEqual(resultat.hour, 13)
        self.assertEqual(resultat.day, 1)

    def test_periodicite_tous_les_jours(self):
        """tous_les_jours doit ajouter exactement 1 jour"""
        resultat = calculer_prochain_scan(self.date_base, "tous_les_jours")
        self.assertEqual(resultat.day, 2)

    def test_periodicite_toutes_les_semaines(self):
        """toutes_les_semaines doit ajouter exactement 7 jours"""
        resultat = calculer_prochain_scan(self.date_base, "toutes_les_semaines")
        self.assertEqual(resultat.day, 8)

    def test_periodicite_tous_les_mois(self):
        """tous_les_mois doit ajouter 30 jours"""
        resultat = calculer_prochain_scan(self.date_base, "tous_les_mois")
        self.assertEqual(resultat.day, 31)

    def test_periodicite_inconnue_retourne_none(self):
        """Une periodicite invalide doit retourner None"""
        self.assertIsNone(calculer_prochain_scan(self.date_base, "jamais"))
        self.assertIsNone(calculer_prochain_scan(self.date_base, ""))
        self.assertIsNone(calculer_prochain_scan(self.date_base, None))


class NormalizePortsTest(TestCase):
    """Tests pour la normalisation de la liste de ports du scanner."""

    def test_liste_vide_donne_tous_les_ports(self):
        """Sans ports specifies, le scanner doit cibler les 65535 ports"""
        scanner = SocketScanner("127.0.0.1", ports=[])
        self.assertEqual(scanner.total_ports, 65535)

    def test_liste_avec_doublons_est_dedupliquee(self):
        """Les doublons dans la liste de ports doivent etre supprimes"""
        scanner = SocketScanner("127.0.0.1", ports=[80, 80, 443, 80, 443])
        self.assertEqual(scanner.total_ports, 2)
        self.assertIn(80, scanner.ports)
        self.assertIn(443, scanner.ports)

    def test_ports_hors_plage_sont_ignores(self):
        """Les ports < 1 ou > 65535 doivent etre filtres"""
        scanner = SocketScanner("127.0.0.1", ports=[0, 80, 100000, 443, -5])
        self.assertEqual(set(scanner.ports), {80, 443})

    def test_valeurs_non_numeriques_sont_ignorees(self):
        """Les valeurs qui ne peuvent pas etre converties en int doivent etre ignorees"""
        scanner = SocketScanner("127.0.0.1", ports=["80", "abc", None, 443])
        self.assertEqual(set(scanner.ports), {80, 443})


class BuildCpeFieldsTest(TestCase):
    """Tests pour la construction des chaines CPE."""

    def test_cpe_name_complet_si_toutes_infos_connues(self):
        """Avec part, vendor, produit et version connus, on construit un cpe_name complet"""
        scanner = SocketScanner("127.0.0.1", ports=[80])
        info = {
            "part": "a",
            "vendor": "apache",
            "produit": "Apache",
            "version": "2.4.41",
            "cpe_name": None,
            "cpe_match_string": None,
        }
        scanner.build_cpe_fields(info)

        self.assertEqual(
            info["cpe_name"],
            "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*",
        )
        self.assertIsNone(info["cpe_match_string"])

    def test_cpe_match_string_avec_wildcards_si_infos_incompletes(self):
        """Si une info est manquante, on construit un cpe_match_string avec des wildcards"""
        scanner = SocketScanner("127.0.0.1", ports=[80])
        info = {
            "part": "a",
            "vendor": "???",
            "produit": "Apache",
            "version": "???",
            "cpe_name": None,
            "cpe_match_string": None,
        }
        scanner.build_cpe_fields(info)

        self.assertIsNone(info["cpe_name"])
        self.assertIn("apache", info["cpe_match_string"])
        self.assertIn("http_server", info["cpe_match_string"])


class BuildScanVersionLabelTest(TestCase):
    """Tests pour le label encodant les ports cibles dans le champ version_scanner."""

    def test_sans_ports_retourne_label_simple(self):
        """Pour un scan complet, le label doit etre simplement SocketScanner"""
        self.assertEqual(build_scan_version_label(), "SocketScanner")
        self.assertEqual(build_scan_version_label([]), "SocketScanner")
        self.assertEqual(build_scan_version_label(None), "SocketScanner")

    def test_avec_ports_encode_la_liste_triee(self):
        """Les ports doivent etre tries et dedupliques dans le label"""
        self.assertEqual(
            build_scan_version_label([443, 80, 443]),
            "SocketScanner[ports:80,443]",
        )


class ScanProgressTest(TestCase):
    """Tests pour le suivi en memoire de la progression des scans."""

    def setUp(self):
        # On garantit que la cle est nettoyee entre les tests
        pop_scan_progress("test-scan-1")
        pop_scan_progress("test-scan-2")

    def tearDown(self):
        pop_scan_progress("test-scan-1")
        pop_scan_progress("test-scan-2")

    def test_set_puis_get_retourne_le_payload(self):
        """Apres set_scan_progress, get_scan_progress doit retourner les memes valeurs"""
        set_scan_progress("test-scan-1", status="en_cours", ports_open=5)
        payload = get_scan_progress("test-scan-1")

        self.assertEqual(payload["status"], "en_cours")
        self.assertEqual(payload["ports_open"], 5)
        # La cle interne _expires_at ne doit pas etre exposee
        self.assertNotIn("_expires_at", payload)

    def test_set_fusionne_les_valeurs(self):
        """Plusieurs set_scan_progress doivent fusionner les cles existantes"""
        set_scan_progress("test-scan-1", status="en_cours", ports_open=2)
        set_scan_progress("test-scan-1", ports_open=10)

        payload = get_scan_progress("test-scan-1")
        # status reste, ports_open est mis a jour
        self.assertEqual(payload["status"], "en_cours")
        self.assertEqual(payload["ports_open"], 10)

    def test_get_retourne_none_si_inconnu(self):
        """get_scan_progress doit retourner None pour un scan jamais enregistre"""
        self.assertIsNone(get_scan_progress("scan-jamais-vu"))

    def test_pop_supprime_le_payload(self):
        """pop_scan_progress doit retourner le payload puis le supprimer"""
        set_scan_progress("test-scan-2", status="complete")

        payload = pop_scan_progress("test-scan-2")
        self.assertEqual(payload["status"], "complete")

        # Apres pop, get doit retourner None
        self.assertIsNone(get_scan_progress("test-scan-2"))


class FullFlowTest(TestCase):

    def test_full_service_key_flow(self):
        user = User.objects.create_user(
            username="fullflow",
            password="testpass123"
        )

        cible = Cible.objects.create(
            owner=user,
            adresse="127.0.0.1"
        )

        scan = Scan.objects.create(
            cible=cible,
            owner=user
        )

        service = Service.objects.create(
            scan=scan,
            port=22,
            protocole="tcp",
            nom_service="ssh",
            produit="OpenSSH",
            version="8.2",
            cpe_name=None
        )

        result = get_service_lookup_key(service)

        self.assertEqual(
            result,
            "service::ssh|openssh|8.2"
        )