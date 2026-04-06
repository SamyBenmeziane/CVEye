from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_http_methods
from django.contrib.auth.models import User

from app_core.models import InstallationConfig
from .forms import LoginForm, RegisterForm
from .models import EmailVerificationToken, UserProfile
from .utils import (
    get_client_ip,
    is_ip_banned,
    register_failed_attempt,
    reset_attempts,
    send_verification_email,
    resend_verification_email,
)


def home_view(request):
    config = InstallationConfig.load()

    if not config.is_installed:
        return redirect("install")

    if request.user.is_authenticated:
        return redirect("scans")

    return redirect("accounts:login")


@require_http_methods(["GET", "POST"])
def login_view(request):
    config = InstallationConfig.load()

    if not config.is_installed:
        return redirect("install")

    if request.user.is_authenticated:
        return redirect("scans")

    ip_address = get_client_ip(request)
    if ip_address and is_ip_banned(ip_address):
        return render(request, "app_accounts/ip_banned.html", status=403)

    form = LoginForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        username = form.cleaned_data["username"]
        password = form.cleaned_data["password"]

        user = authenticate(request, username=username, password=password)

        if user is None:
            banned_now = register_failed_attempt(ip_address, username=username)
            if banned_now:
                return render(request, "app_accounts/ip_banned.html", status=403)

            messages.error(request, "Nom d'utilisateur ou mot de passe invalide.")
            return render(request, "app_accounts/login.html", {"form": form})

        profile, _ = UserProfile.objects.get_or_create(user=user)

        if not profile.email_verified:
            messages.error(
                request,
                "Vous devez confirmer votre adresse email avant de vous connecter."
            )
            return render(
                request,
                "app_accounts/login.html",
                {
                    "form": form,
                    "show_resend_link": True,
                    "prefill_username": username,
                },
            )

        if not user.is_active:
            messages.error(request, "Votre compte est inactif.")
            return render(request, "app_accounts/login.html", {"form": form})

        reset_attempts(ip_address)
        login(request, user)
        return redirect("scans")

    return render(request, "app_accounts/login.html", {"form": form})


@require_http_methods(["GET", "POST"])
def register_view(request):
    config = InstallationConfig.load()

    if not config.is_installed:
        return redirect("install")

    if request.user.is_authenticated:
        return redirect("scans")

    form = RegisterForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        try:
            with transaction.atomic():
                user = form.save(commit=False)
                user.email = form.cleaned_data["email"]
                user.is_active = False
                user.set_password(form.cleaned_data["password1"])
                user.save()

                UserProfile.objects.create(user=user, email_verified=False)
                send_verification_email(request, user)

            return render(
                request,
                "app_accounts/email_verification_sent.html",
                {
                    "email": user.email,
                    "username": user.username,
                },
            )

        except Exception as exc:
            messages.error(
                request,
                f"Impossible d'envoyer le mail de confirmation : {exc}"
            )

    return render(request, "app_accounts/register.html", {"form": form})


@require_http_methods(["GET", "POST"])
def resend_verification_view(request):
    config = InstallationConfig.load()

    if not config.is_installed:
        return redirect("install")

    username = request.POST.get("username") or request.GET.get("username")

    if not username:
        messages.error(request, "Nom d'utilisateur manquant.")
        return redirect("accounts:login")

    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        messages.error(request, "Utilisateur introuvable.")
        return redirect("accounts:login")

    profile, _ = UserProfile.objects.get_or_create(user=user)

    if profile.email_verified:
        messages.info(request, "Cet email est déjà vérifié.")
        return redirect("accounts:login")

    try:
        resend_verification_email(request, user)
        return render(
            request,
            "app_accounts/email_verification_sent.html",
            {
                "email": user.email,
                "username": user.username,
                "resent": True,
            },
        )
    except Exception as exc:
        messages.error(request, f"Impossible d'envoyer le mail : {exc}")
        return redirect("accounts:login")


def verify_email_view(request, token):
    token_obj = get_object_or_404(EmailVerificationToken, token=token)

    if token_obj.is_used:
        return render(request, "app_accounts/email_verified.html", {"already_used": True})

    if token_obj.is_expired():
        return render(request, "app_accounts/email_verification_invalid.html")

    user = token_obj.user
    profile, _ = UserProfile.objects.get_or_create(user=user)

    profile.email_verified = True
    profile.save()

    user.is_active = True
    user.save()

    token_obj.is_used = True
    token_obj.save()

    return render(request, "app_accounts/email_verified.html", {"already_used": False})


def logout_view(request):
    logout(request)
    messages.success(request, "Vous êtes maintenant déconnecté.")
    return redirect("accounts:login")