from django.test import TestCase
from unittest.mock import patch

from app_scan.scanner import SocketScanner

from app_scan.scan_execution import get_service_lookup_key
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