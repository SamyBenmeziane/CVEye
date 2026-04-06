from django.shortcuts import render, redirect
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core.mail import EmailMultiAlternatives, get_connection

from .forms import InstallationForm
from .models import InstallationConfig
from app_accounts.models import UserProfile


def install_view(request):
    config = InstallationConfig.load()

    if config.is_installed:
        return redirect("accounts:login")

    if request.method == "POST":
        form = InstallationForm(request.POST)

        if form.is_valid():
            User = get_user_model()

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
                username=admin_email,
                email=admin_email,
                password=admin_password
            )

            UserProfile.objects.create(user=admin_user, email_verified=True)

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