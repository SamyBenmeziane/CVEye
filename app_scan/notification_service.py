from app_core.email_utils import envoyer_email
from app_dashboard.reporting import build_target_report_filename, generate_target_report_pdf
from app_security.models import Vulnerability


def _build_scan_report_attachment(scan_obj):
    """Génère le rapport PDF du scan et le retourne sous forme de liste de pièce jointe prête pour envoyer_email.

    Retourne une liste vide si la génération échoue.
    """
    try:
        pdf_content = generate_target_report_pdf(scan_obj.cible, [scan_obj], scan_obj.owner)
    except Exception:
        return []

    return [
        {
            "filename": build_target_report_filename(scan_obj.cible, 1),
            "content": pdf_content,
            "mimetype": "application/pdf",
        }
    ]


def envoyer_notification_resultat_scan(scan_obj):
    """Envoie un e-mail de notification adapté au résultat du scan avec le rapport PDF en pièce jointe.

    Trois cas possibles : serveur hors ligne (server_hs), vulnérabilités détectées, ou scan sans incident.
    Ne fait rien si l'utilisateur propriétaire n'a pas d'adresse e-mail.
    """
    utilisateur = scan_obj.owner
    cible = scan_obj.cible

    if not utilisateur or not utilisateur.email:
        return

    pieces_jointes = _build_scan_report_attachment(scan_obj)

    # On choisit le message selon trois cas simple serveur HS vuln en base ou scan propre
    if scan_obj.server_hs:
        sujet = f"[CVEye] Serveur HS detecte - {cible.adresse}"
        message = (
            f"Bonjour,\n\n"
            f"Le serveur {cible.adresse} est actuellement hors ligne.\n"
            f"Aucun port ouvert n'a ete detecte et le ping ne repond pas.\n\n"
            f"Date du scan : {scan_obj.date_fin}\n\n"
            f"Le rapport PDF du scan est joint a ce message."
        )
        envoyer_email(utilisateur.email, sujet, message, pieces_jointes=pieces_jointes)
        return

    vulnerabilites = Vulnerability.objects.filter(service__scan=scan_obj).select_related("service")

    if vulnerabilites.exists():
        lignes = []
        for vuln in vulnerabilites:
            service = vuln.service
            lignes.append(
                f"- CVE : {vuln.cve_id} | "
                f"Serveur : {cible.adresse} | "
                f"Port : {service.port} | "
                f"Service : {service.nom_service} | "
                f"Version : {service.version or service.produit or 'Inconnue'}"
            )

        sujet = f"[CVEye] Vulnerabilites detectees - {cible.adresse}"
        message = (
            f"Bonjour,\n\n"
            f"Des vulnerabilites ont ete detectees sur le serveur {cible.adresse}.\n\n"
            f"Details :\n"
            + "\n".join(lignes)
            + "\n\nLe rapport PDF du scan est joint a ce message.\n\nMerci."
        )
        envoyer_email(utilisateur.email, sujet, message, pieces_jointes=pieces_jointes)
        return

    sujet = f"[CVEye] Scan OK - {cible.adresse}"
    message = (
        f"Bonjour,\n\n"
        f"Le scan du serveur {cible.adresse} s'est termine sans incident.\n"
        f"Aucun serveur HS ni aucune vulnerabilite n'ont ete detectes.\n\n"
        f"Date du scan : {scan_obj.date_fin}\n\n"
        f"Le rapport PDF du scan est joint a ce message."
    )
    envoyer_email(utilisateur.email, sujet, message, pieces_jointes=pieces_jointes)
