import re
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

from django.conf import settings


class SocketScanner:
    TOTAL_PORTS = 65535
    DEFAULT_MAX_THREADS = getattr(settings, "SCAN_MAX_THREADS", 5000)

    def __init__(self, addr_ip, max_threads=None, progress_callback=None, ports=None):
        """Initialise le scanner avec l'adresse cible, le nombre de threads, un callback de progression
        et la liste de ports à scanner (par défaut tous les ports de 1 à 65535)."""
        self.addr_ip = addr_ip
        self.ports = self.normalize_ports(ports)
        self.total_ports = len(self.ports)
        configured_threads = self.DEFAULT_MAX_THREADS if max_threads is None else max_threads
        self.max_threads = max(1, min(int(configured_threads), self.total_ports))
        self.progress_callback = progress_callback
        self.resultat = {}
        self.lock = threading.Lock()
        self.progress_lock = threading.Lock()
        self.scanned_ports = 0

        # Chaque sonde tente de reveiller un service pour recuperer une banniere utile
        self.probes = [
            {"nom": "HTTP", "req": b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"},
            {"nom": "NULL", "req": b"\r\n"},
            # Pour le moment cette sonde ne sert pas vraiment mais elle reste la pour les essais
            {"nom": "BITTORRENT", "req": b"\x13BitTorrent protocol"},
        ]

    def normalize_ports(self, ports):
        """Convertit, déduplique et valide la liste de ports. Retourne tous les ports si la liste est vide."""
        if not ports:
            return list(range(1, self.TOTAL_PORTS + 1))

        normalized = []
        for port in ports:
            try:
                port_int = int(port)
            except (TypeError, ValueError):
                continue

            if 1 <= port_int <= self.TOTAL_PORTS and port_int not in normalized:
                normalized.append(port_int)

        return normalized or list(range(1, self.TOTAL_PORTS + 1))

    def sanitize_text(self, value):
        """Supprime les octets nuls d'une chaîne pour éviter les problèmes lors du stockage en base."""
        if value is None:
            return None
        return str(value).replace("\x00", "")

    def verif_port(self, port):
        """Teste si un port TCP est ouvert et délègue l'identification du service si c'est le cas."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.8)

        try:
            result = sock.connect_ex((self.addr_ip, port))
            if result == 0:
                self.identifier_service(port)
        except Exception:
            pass
        finally:
            sock.close()
            self.increment_progress()

    def increment_progress(self):
        """Incrémente le compteur de ports scannés de façon thread-safe et appelle le callback de progression."""
        if not self.progress_callback:
            return

        with self.progress_lock:
            self.scanned_ports += 1
            scanned_ports = self.scanned_ports

        self.progress_callback(scanned_ports, self.total_ports)

    def identifier_service(self, port):
        """Envoie des sondes successives sur le port ouvert pour obtenir une bannière d'identification."""
        banniere = ""

        for probe in self.probes:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.2)
                sock.connect((self.addr_ip, port))

                if probe["req"]:
                    sock.send(probe["req"])

                reponse = sock.recv(4096)
                if reponse:
                    banniere = self.sanitize_text(
                        reponse.decode("utf-8", errors="ignore")
                    )
                    sock.close()
                    break
                sock.close()
            except Exception:
                continue

        self.process_data(port, banniere)

    def process_data(self, port, banniere):
        """Analyse la bannière pour identifier le service (HTTP, SSH, FTP) et construit les champs CPE."""
        info = {
            "port": port,
            "service": "unknown",
            "version": "???",
            "produit": "???",
            "headers": {},
            "banniere": banniere,
            "part": "???",
            "vendor": "???",
            "cpe_name": None,
            "cpe_match_string": None,
        }

        if not banniere:
            try:
                # Si on na pas de banniere on tente au moins une estimation simple avec le port
                info["service"] = socket.getservbyport(port) + " : GUESSED" if port < 1024 else "unknown"
            except OSError:
                info["service"] = "unknown"
        else:
            if "HTTP/" in banniere or "Server:" in banniere:
                info["service"] = "http"
                info["part"] = "a"
                for line in banniere.split("\n"):
                    if ":" in line:
                        key, value = line.split(":", 1)
                        info["headers"][self.sanitize_text(key.strip().lower())] = (
                            self.sanitize_text(value.strip())
                        )

                info["produit"] = self.sanitize_text(
                    info["headers"].get("server", "???")
                )
                info["version"] = self.parse_version(info["produit"])

            elif "SSH-" in banniere:
                info["service"] = "ssh"
                info["part"] = "a"
                # Ici on fait un raccourci volontaire qui suffit pour les recherches de CVE
                info["vendor"] = "openbsd" if "openssh" in banniere.lower() else "???"
                info["produit"] = "OpenSSH" if "openssh" in banniere.lower() else "SSH-Server"
                info["version"] = self.parse_version(banniere)

            elif "220" in banniere:
                if "ftp" in banniere.lower():
                    info["service"] = "ftp"
                info["part"] = "a"
                info["version"] = self.parse_version(banniere)

        # On force certains headers a exister pour eviter plein de tests plus loin dans lapp
        if info["service"] == "http":
            for header in ["keepalive", "acceptranges", "null", "server", "etag"]:
                if header not in info["headers"]:
                    info["headers"][header] = "???"

        for field in ["service", "version", "produit", "banniere", "part", "vendor"]:
            info[field] = self.sanitize_text(info[field])

        self.build_cpe_fields(info)

        with self.lock:
            self.resultat[port] = info

    def parse_version(self, text):
        """Extrait le premier numéro de version au format X.Y ou X.Y.Z trouvé dans le texte."""
        match = re.search(r"(\d+\.\d+(\.\d+)?)", text)
        return match.group(1) if match else "???"

    def normalize_product(self, produit):
        """Normalise le nom du produit en minuscules avec underscores pour les champs CPE."""
        if not produit or produit == "???":
            return "???"

        produit_min = produit.lower()

        if "openssh" in produit_min:
            return "openssh"
        if "apache" in produit_min:
            return "http_server"
        if "ftp" in produit_min:
            return "ftp"

        return produit_min.replace(" ", "_")

    def detect_vendor(self, produit):
        """Déduit le nom de l'éditeur (vendor) à partir du nom du produit détecté."""
        if not produit or produit == "???":
            return "???"

        produit_min = produit.lower()

        if "openssh" in produit_min:
            return "openbsd"
        if "apache" in produit_min:
            return "apache"

        return "???"

    def build_cpe_fields(self, info):
        """Construit cpe_name (CPE complet) ou cpe_match_string (CPE avec wildcards) selon les données disponibles."""
        produit_normalise = self.normalize_product(info["produit"])

        if info["vendor"] == "???":
            info["vendor"] = self.detect_vendor(info["produit"])

        # Si tout est connu on fait un CPE complet sinon on garde une version plus large
        if (
            info["part"] not in ["???", "unknown", "", None]
            and info["vendor"] not in ["???", "unknown", "", None]
            and produit_normalise not in ["???", "unknown", "", None]
            and info["version"] not in ["???", "unknown", "", None]
        ):
            info["cpe_name"] = (
                f"cpe:2.3:{info['part']}:{info['vendor']}:{produit_normalise}:"
                f"{info['version']}:*:*:*:*:*:*:*"
            )
        else:
            part = info["part"] if info["part"] not in ["???", "unknown", "", None] else "*"
            vendor = info["vendor"] if info["vendor"] not in ["???", "unknown", "", None] else "*"
            product = produit_normalise if produit_normalise not in ["???", "unknown", "", None] else "*"
            version = info["version"] if info["version"] not in ["???", "unknown", "", None] else "*"
            info["cpe_match_string"] = (
                f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
            )

    def run(self):
        """Lance le scan en parallèle sur tous les ports configurés et retourne les ports ouverts détectés."""
        with ThreadPoolExecutor(max_workers=min(self.max_threads, self.total_ports)) as executor:
            executor.map(self.verif_port, self.ports)
        return self.resultat
