from django.core.mail import EmailMultiAlternatives
from django.core.mail.backends.smtp import EmailBackend

from app_core.models import InstallationConfig


def get_email_backend():
    """Instancie le backend SMTP Django avec les paramètres stockés dans InstallationConfig."""
    config = InstallationConfig.load()

    return EmailBackend(
        host=config.smtp_host,
        port=config.smtp_port,
        username=config.smtp_username,
        password=config.smtp_password,
        use_tls=config.smtp_use_tls,
        use_ssl=config.smtp_use_ssl,
        fail_silently=False,
    )


def envoyer_email(destinataire, sujet, contenu_texte, pieces_jointes=None):
    """Envoie un email via le backend SMTP configuré avec des pièces jointes facultatives.

    Chaque pièce jointe est un dict avec les clés 'filename', 'content' et 'mimetype'.
    Ne fait rien si le destinataire est vide.
    """
    if not destinataire:
        return

    config = InstallationConfig.load()
    backend = get_email_backend()

    email = EmailMultiAlternatives(
        subject=sujet,
        body=contenu_texte,
        from_email=config.smtp_from_email,
        to=[destinataire],
        connection=backend,
    )

    # On attache seulement les pieces vraiment completes pour eviter un mail casse
    for piece_jointe in pieces_jointes or []:
        if not piece_jointe:
            continue

        nom_fichier = piece_jointe.get("filename")
        contenu = piece_jointe.get("content")
        mime_type = piece_jointe.get("mimetype", "application/octet-stream")

        if nom_fichier and contenu is not None:
            email.attach(nom_fichier, contenu, mime_type)

    email.send()
