from django.shortcuts import render, redirect
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core.mail import EmailMultiAlternatives, get_connection

from .forms import InstallationForm
from .models import InstallationConfig
from app_accounts.models import UserProfile
from app_accounts.utils import generate_unique_username


def install_view(request):
    """Gère l'assistant d'installation initiale : création du super administrateur et configuration SMTP.

    Vérifie qu'aucun utilisateur n'existe déjà, teste la connexion SMTP avant de sauvegarder,
    puis crée le compte administrateur, son profil et la configuration du site.
    """
    config = InstallationConfig.load()

    if config.is_installed:
        return redirect("accounts:login")

    if request.method == "POST":
        form = InstallationForm(request.POST)

        if form.is_valid():
            User = get_user_model()

            # On refuse linstallation si un utilisateur existe deja pour eviter une reinitialisation sauvage
            if User.objects.exists():
                return render(
                    request,
                    "app_dashboard/install.html",
                    {
                        "form": form,
                        "error_message": "Un utilisateur existe déjà. Installation initiale non autorisée."
                    }
                )

            admin_email = form.cleaned_data["admin_email"]
            admin_password = form.cleaned_data["admin_password"]
            admin_first_name = form.cleaned_data["admin_first_name"]
            admin_last_name = form.cleaned_data["admin_last_name"]
            admin_username = generate_unique_username(admin_first_name, admin_last_name)

            smtp_host = form.cleaned_data.get("smtp_host", "")
            smtp_port = form.cleaned_data.get("smtp_port") or 587
            smtp_username = form.cleaned_data.get("smtp_username", "")
            smtp_password = form.cleaned_data.get("smtp_password", "")
            smtp_from_email = form.cleaned_data.get("smtp_from_email", "")
            smtp_use_tls = form.cleaned_data.get("smtp_use_tls", False)
            smtp_use_ssl = form.cleaned_data.get("smtp_use_ssl", False)

            if smtp_use_tls and smtp_use_ssl:
                return render(
                    request,
                    "app_dashboard/install.html",
                    {
                        "form": form,
                        "error_message": "Vous ne pouvez pas activer TLS et SSL en même temps."
                    }
                )

            # On teste le SMTP tout de suite pour ne pas sauver une config inutilisable
            try:
                connection = get_connection(
                    backend="django.core.mail.backends.smtp.EmailBackend",
                    host=smtp_host,
                    port=smtp_port,
                    username=smtp_username,
                    password=smtp_password,
                    use_tls=smtp_use_tls,
                    use_ssl=smtp_use_ssl,
                    fail_silently=False,
                )

                test_message = EmailMultiAlternatives(
                    subject="Test SMTP CVEye",
                    body="La configuration SMTP de CVEye est valide.",
                    from_email=smtp_from_email or smtp_username,
                    to=[admin_email],
                    connection=connection,
                )
                test_message.send()

            except Exception as exc:
                return render(
                    request,
                    "app_dashboard/install.html",
                    {
                        "form": form,
                        "error_message": f"Configuration SMTP invalide : {exc}"
                    }
                )

            admin_user = User.objects.create_superuser(
                username=admin_username,
                email=admin_email,
                password=admin_password,
                first_name=admin_first_name,
                last_name=admin_last_name,
            )

            UserProfile.objects.create(
                user=admin_user,
                email_verified=True,
                admin_approved=True,
                approved_at=timezone.now(),
                approved_by=admin_user,
            )

            config.site_name = form.cleaned_data["site_name"]
            config.smtp_host = smtp_host
            config.smtp_port = smtp_port
            config.smtp_username = smtp_username
            config.smtp_password = smtp_password
            config.smtp_from_email = smtp_from_email
            config.smtp_use_tls = smtp_use_tls
            config.smtp_use_ssl = smtp_use_ssl
            config.is_installed = True
            config.installed_at = timezone.now()
            config.save()

            return redirect("accounts:login")
    else:
        form = InstallationForm(initial={
            "site_name": "CVEye",
            "smtp_port": 587,
            "smtp_use_tls": True,
            "smtp_use_ssl": False,
        })

    return render(request, "app_dashboard/install.html", {"form": form})
