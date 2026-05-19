from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sessions.models import Session
from django.core.mail import EmailMultiAlternatives, get_connection
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
import re
import unicodedata

from app_core.models import InstallationConfig
from .models import BannedIP, EmailVerificationToken, LoginAttempt


def build_username_base(first_name, last_name):
    """Construit une base ASCII normalisée pour le nom d'utilisateur à partir du prénom et du nom.

    Supprime les accents, les caractères spéciaux et sépare les parties par des points.
    Le résultat est tronqué à 150 caractères.
    """
    def normalize(value):
        """Convertit une chaîne en ASCII minuscule avec des points comme séparateurs."""
        ascii_value = unicodedata.normalize("NFKD", value or "").encode("ascii", "ignore").decode("ascii")
        ascii_value = re.sub(r"[^a-zA-Z0-9]+", " ", ascii_value).strip().lower()
        return ".".join(part for part in ascii_value.split() if part)

    first_part = normalize(first_name)
    last_part = normalize(last_name)
    base = ".".join(part for part in [first_part, last_part] if part)
    return base[:150]


def generate_unique_username(first_name, last_name, *, exclude_user_id=None):
    """Génère un nom d'utilisateur unique en base de données à partir du prénom et du nom.

    Si la base normalisée est déjà prise, ajoute un suffixe numérique incrémental.
    Le paramètre exclude_user_id permet d'exclure un compte existant lors d'une mise à jour.
    """
    User = get_user_model()
    base = build_username_base(first_name, last_name)

    if not base:
        base = "utilisateur"

    username = base
    suffix = 2

    while True:
        qs = User.objects.filter(username=username)
        if exclude_user_id is not None:
            qs = qs.exclude(pk=exclude_user_id)

        # On ajoute un numero tant que le nom est deja pris
        if not qs.exists():
            return username

        suffix_text = str(suffix)
        username = f"{base[:150 - len(suffix_text)]}{suffix_text}"
        suffix += 1


def get_client_ip(request):
    """Extrait l'adresse IP réelle du client depuis les en-têtes HTTP.

    Prend en compte l'en-tête X-Forwarded-For pour les déploiements derrière un proxy.
    """
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


def is_ip_banned(ip_address):
    """Vérifie si une adresse IP figure dans la table des IP bannies."""
    return BannedIP.objects.filter(ip_address=ip_address).exists()


def register_failed_attempt(ip_address, username=""):
    """Enregistre un échec de connexion et bannit l'IP après trois tentatives échouées.

    Retourne True si l'IP vient d'être bannie lors de cet appel, False sinon.
    """
    if not ip_address:
        return False

    attempt, _ = LoginAttempt.objects.get_or_create(ip_address=ip_address)
    attempt.attempt_count += 1
    attempt.last_username = username
    attempt.save()

    # Apres trois echecs on bannit lIP et on remet le compteur a zero
    if attempt.attempt_count >= 3:
        BannedIP.objects.get_or_create(
            ip_address=ip_address,
            defaults={"reason": "3 tentatives de connexion invalides"},
        )
        attempt.delete()
        return True

    return False


def reset_attempts(ip_address):
    """Supprime les tentatives de connexion échouées enregistrées pour cette adresse IP."""
    if ip_address:
        LoginAttempt.objects.filter(ip_address=ip_address).delete()


def create_verification_token(user):
    """Crée et persiste un jeton de vérification d'email pour l'utilisateur donné."""
    return EmailVerificationToken.objects.create(user=user)


def sync_user_activation_state(user, profile=None, *, save=True):
    """Synchronise le champ is_active de l'utilisateur avec les règles du profil.

    Un super administrateur est toujours actif. Pour les autres, l'état découle de
    profile.can_login(). Si save=True et que l'état change, la mise à jour est persistée.
    """
    profile = profile or getattr(user, "userprofile", None)
    if profile is None:
        return user.is_active

    # Un super admin reste actif meme si les autres validations ne sont pas faites
    if profile.is_superadmin:
        should_be_active = True
    else:
        should_be_active = profile.can_login()

    if user.is_active != should_be_active:
        user.is_active = should_be_active
        if save:
            user.save(update_fields=["is_active"])

    return should_be_active


def get_smtp_connection():
    """Instancie et retourne une connexion SMTP Django configurée depuis InstallationConfig."""
    config = InstallationConfig.load()

    return get_connection(
        backend="django.core.mail.backends.smtp.EmailBackend",
        host=config.smtp_host,
        port=config.smtp_port or 587,
        username=config.smtp_username or "",
        password=config.smtp_password or "",
        use_tls=config.smtp_use_tls,
        use_ssl=config.smtp_use_ssl,
        fail_silently=False,
    )


def send_verification_email(request, user):
    """Génère un jeton de vérification et envoie l'email de confirmation à l'utilisateur."""
    config = InstallationConfig.load()
    token_obj = create_verification_token(user)

    # On genere un lien complet pour que le mail marche depuis nimporte ou
    verify_url = request.build_absolute_uri(
        reverse("accounts:verify_email", kwargs={"token": str(token_obj.token)})
    )

    context = {
        "user": user,
        "verify_url": verify_url,
        "site_name": config.site_name or "CVEye",
    }

    subject = "Vérification de votre compte CVEye"
    from_email = config.smtp_from_email or config.smtp_username
    recipient_list = [user.email]

    text_body = render_to_string("app_accounts/email_verification_email.txt", context)
    html_body = render_to_string("app_accounts/email_verification_email.html", context)

    connection = get_smtp_connection()
    message = EmailMultiAlternatives(
        subject=subject,
        body=text_body,
        from_email=from_email,
        to=recipient_list,
        connection=connection,
    )
    message.attach_alternative(html_body, "text/html")
    message.send()


def send_account_approved_email(user):
    """Envoie un email à l'utilisateur pour l'informer que son compte a été approuvé."""
    config = InstallationConfig.load()
    context = {
        "user": user,
        "site_name": config.site_name or "CVEye",
    }

    subject = "Votre compte CVEye a été validé"
    from_email = config.smtp_from_email or config.smtp_username
    recipient_list = [user.email]

    text_body = render_to_string("app_accounts/account_approved_email.txt", context)
    html_body = render_to_string("app_accounts/account_approved_email.html", context)

    connection = get_smtp_connection()
    message = EmailMultiAlternatives(
        subject=subject,
        body=text_body,
        from_email=from_email,
        to=recipient_list,
        connection=connection,
    )
    message.attach_alternative(html_body, "text/html")
    message.send()


def build_password_reset_url(request, user):
    """Construit l'URL absolue signée pour la réinitialisation du mot de passe de l'utilisateur."""
    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    return request.build_absolute_uri(
        reverse(
            "accounts:password_reset_confirm",
            kwargs={"uidb64": uidb64, "token": token},
        )
    )


def send_password_reset_email(request, user):
    """Envoie à l'utilisateur un email contenant le lien signé de réinitialisation du mot de passe."""
    config = InstallationConfig.load()
    reset_url = build_password_reset_url(request, user)
    context = {
        "user": user,
        "reset_url": reset_url,
        "site_name": config.site_name or "CVEye",
    }

    subject = "Reinitialisation de votre mot de passe CVEye"
    from_email = config.smtp_from_email or config.smtp_username
    recipient_list = [user.email]

    text_body = render_to_string("app_accounts/password_reset_email.txt", context)
    html_body = render_to_string("app_accounts/password_reset_email.html", context)

    connection = get_smtp_connection()
    message = EmailMultiAlternatives(
        subject=subject,
        body=text_body,
        from_email=from_email,
        to=recipient_list,
        connection=connection,
    )
    message.attach_alternative(html_body, "text/html")
    message.send()


def resend_verification_email(request, user):
    """Invalide les jetons de vérification existants non utilisés et en envoie un nouveau."""
    # On supprime les anciens jetons pour ne garder que le plus recent
    EmailVerificationToken.objects.filter(user=user, is_used=False).delete()
    send_verification_email(request, user)


def purge_user_sessions(user):
    """Supprime toutes les sessions Django actives de l'utilisateur pour le déconnecter partout."""
    user_id = str(user.pk)
    for session in Session.objects.all():
        data = session.get_decoded()
        if data.get("_auth_user_id") == user_id:
            session.delete()
