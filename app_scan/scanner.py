import re
import socket
import threading
from concurrent.futures import ThreadPoolExecutor


class SocketScanner:
    def __init__(self, addr_ip, max_threads=5000):
        self.addr_ip = addr_ip
        self.max_threads = max_threads
        self.resultat = {}
        self.lock = threading.Lock()

        self.probes = [
            {"nom": "HTTP", "req": b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"},
            {"nom": "NULL", "req": b"\r\n"},
            {"nom": "BITTORRENT", "req": b"\x13BitTorrent protocol"},
        ]

    def sanitize_text(self, value):
        if value is None:
            return None
        return str(value).replace("\x00", "")

    def verif_port(self, port):
        """Verification de l'ouverture des ports, identification et extraction."""
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

    def identifier_service(self, port):
        """Identifie le service expose sur un port ouvert."""
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
        """Extrait les informations detectees pour un service."""
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
                info["service"] = socket.getservbyport(port) if port < 1024 else "unknown"
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
                info["vendor"] = "openbsd" if "openssh" in banniere.lower() else "???"
                info["produit"] = "OpenSSH" if "openssh" in banniere.lower() else "SSH-Server"
                info["version"] = self.parse_version(banniere)

            elif "220" in banniere:
                if "ftp" in banniere.lower():
                    info["service"] = "ftp"
                info["part"] = "a"
                info["version"] = self.parse_version(banniere)

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
        match = re.search(r"(\d+\.\d+(\.\d+)?)", text)
        return match.group(1) if match else "???"

    def normalize_product(self, produit):
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
        if not produit or produit == "???":
            return "???"

        produit_min = produit.lower()

        if "openssh" in produit_min:
            return "openbsd"
        if "apache" in produit_min:
            return "apache"

        return "???"

    def build_cpe_fields(self, info):
        produit_normalise = self.normalize_product(info["produit"])

        if info["vendor"] == "???":
            info["vendor"] = self.detect_vendor(info["produit"])

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
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            executor.map(self.verif_port, range(1, 65536))
        return self.resultat
