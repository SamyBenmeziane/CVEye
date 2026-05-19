import platform
import subprocess


def ping_ok(hote: str) -> bool:
    """Vérifie si l'hôte répond à un ping ICMP en adaptant la commande à l'OS (Windows/Linux)."""
    systeme = platform.system().lower()

    # Les options changent entre Windows et Linux donc on choisit la bonne commande ici
    if systeme == "windows":
        commande = ["ping", "-n", "1", "-w", "1000", hote]
    else:
        commande = ["ping", "-c", "1", "-W", "1", hote]

    try:
        resultat = subprocess.run(
            commande,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
        return resultat.returncode == 0
    except Exception:
        return False


def est_serveur_hs(hote: str, resultat_scan: dict) -> bool:
    """Détermine si un serveur est hors ligne : retourne True uniquement si aucun port n'est ouvert
    ET que le ping échoue également.
    """
    aucun_port_ouvert = not bool(resultat_scan)

    if not aucun_port_ouvert:
        return False

    return not ping_ok(hote)
