from django.core.mail import EmailMultiAlternatives, get_connection
from django.template.loader import render_to_string
from django.urls import reverse

from app_core.models import InstallationConfig
from .models import LoginAttempt, BannedIP, EmailVerificationToken


def get_client_ip(request):
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


def is_ip_banned(ip_address):
    return BannedIP.objects.filter(ip_address=ip_address).exists()


def register_failed_attempt(ip_address, username=""):
    if not ip_address:
        return False

    attempt, _ = LoginAttempt.objects.get_or_create(ip_address=ip_address)
    attempt.attempt_count += 1
    attempt.last_username = username
    attempt.save()

    if attempt.attempt_count >= 3:
        BannedIP.objects.get_or_create(
            ip_address=ip_address,
            defaults={"reason": "3 tentatives de connexion invalides"},
        )
        attempt.delete()
        return True

    return False


def reset_attempts(ip_address):
    if ip_address:
        LoginAttempt.objects.filter(ip_address=ip_address).delete()


def create_verification_token(user):
    return EmailVerificationToken.objects.create(user=user)


def get_smtp_connection():
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
    config = InstallationConfig.load()
    token_obj = create_verification_token(user)

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


def resend_verification_email(request, user):
    EmailVerificationToken.objects.filter(user=user, is_used=False).delete()
    send_verification_email(request, user)