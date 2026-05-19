from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.views.decorators.http import require_http_methods
from app_core.models import InstallationConfig
from .forms import (
    AccountPasswordForm,
    AccountSettingsForm,
    LoginForm,
    PasswordResetConfirmForm,
    PasswordResetRequestForm,
    RegisterForm,
)
from .models import EmailVerificationToken, UserProfile
from .utils import (
    get_client_ip,
    is_ip_banned,
    register_failed_attempt,
    resend_verification_email,
    reset_attempts,
    send_verification_email,
    send_password_reset_email,
    sync_user_activation_state,
)


def home_view(request):
    """Redirige vers l'installation, le tableau de bord ou la connexion selon l'état du site."""
    config = InstallationConfig.load()

    if not config.is_installed:
        return redirect("install")

    if request.user.is_authenticated:
        return redirect("dashboard")

    return redirect("accounts:login")


@require_http_methods(["GET", "POST"])
def login_view(request):
    """Gère l'authentification, vérifie l'état du compte et bloque les IP après trois échecs."""
    config = InstallationConfig.load()

    if not config.is_installed:
        return redirect("install")

    if request.user.is_authenticated:
        return redirect("dashboard")

    ip_address = get_client_ip(request)
    if ip_address and is_ip_banned(ip_address):
        return render(request, "app_accounts/ip_banned.html", status=403)

    form = LoginForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        username = form.cleaned_data["username"]
        password = form.cleaned_data["password"]
        user = User.objects.filter(username=username).first()

        # On compte aussi les erreurs sur un utilisateur qui existe mais avec un mauvais mot de passe
        if not user or not user.check_password(password):
            banned_now = register_failed_attempt(ip_address, username=username)
            if banned_now:
                return render(request, "app_accounts/ip_banned.html", status=403)

            messages.error(request, "Nom d'utilisateur ou mot de passe invalide.")
            return render(request, "app_accounts/login.html", {"form": form})

        profile, _ = UserProfile.objects.get_or_create(user=user)
        sync_user_activation_state(user, profile=profile)
        reset_attempts(ip_address)

        if not profile.email_verified:
            messages.error(
                request,
                "Vous devez confirmer votre adresse email avant de vous connecter.",
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

        if not profile.admin_approved:
            messages.warning(
                request,
                "Votre compte est en attente de validation par un administrateur.",
            )
            return render(request, "app_accounts/login.html", {"form": form})

        if not user.is_active:
            messages.error(request, "Votre compte est inactif.")
            return render(request, "app_accounts/login.html", {"form": form})

        # Si authenticate ne renvoie rien on reutilise lutilisateur deja verifie a la main
        authenticated_user = authenticate(request, username=username, password=password)
        if authenticated_user is None:
            authenticated_user = user
            authenticated_user.backend = settings.AUTHENTICATION_BACKENDS[0]

        login(request, authenticated_user)
        return redirect("dashboard")

    return render(request, "app_accounts/login.html", {"form": form})


@require_http_methods(["GET", "POST"])
def password_reset_request_view(request):
    """Traite la demande de réinitialisation de mot de passe et envoie le lien par email."""
    config = InstallationConfig.load()

    if not config.is_installed:
        return redirect("install")

    if request.user.is_authenticated:
        return redirect("dashboard")

    form = PasswordResetRequestForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        username = form.cleaned_data["username"]
        email = form.cleaned_data["email"]
        user = User.objects.filter(
            username=username,
            email=email,
            is_superuser=False,
        ).first()

        if user:
            try:
                send_password_reset_email(request, user)
            except Exception as exc:
                messages.error(request, f"Impossible d'envoyer le mail de réinitialisation : {exc}")
                return render(request, "app_accounts/password_reset_request.html", {"form": form})

        return render(
            request,
            "app_accounts/password_reset_sent.html",
            {"email": email, "username": username},
        )

    return render(request, "app_accounts/password_reset_request.html", {"form": form})


@require_http_methods(["GET", "POST"])
def password_reset_confirm_view(request, uidb64, token):
    """Valide le lien signé de réinitialisation et permet de définir un nouveau mot de passe."""
    config = InstallationConfig.load()

    if not config.is_installed:
        return redirect("install")

    try:
        user_id = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=user_id, is_superuser=False)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if not user or not default_token_generator.check_token(user, token):
        return render(request, "app_accounts/password_reset_invalid.html", status=400)

    form = PasswordResetConfirmForm(user=user, data=request.POST or None)

    if request.method == "POST" and form.is_valid():
        form.save()
        profile, _ = UserProfile.objects.get_or_create(user=user)
        sync_user_activation_state(user, profile=profile)
        return render(request, "app_accounts/password_reset_complete.html")

    return render(
        request,
        "app_accounts/password_reset_confirm.html",
        {"form": form},
    )


@require_http_methods(["GET", "POST"])
def register_view(request):
    """Crée un nouveau compte utilisateur dans une transaction atomique et envoie l'email de vérification."""
    config = InstallationConfig.load()

    if not config.is_installed:
        return redirect("install")

    if request.user.is_authenticated:
        return redirect("dashboard")

    form = RegisterForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        try:
            # On garde tout dans une transaction pour eviter un compte cree a moitie
            with transaction.atomic():
                user = form.save(commit=False)
                user.first_name = form.cleaned_data["first_name"]
                user.last_name = form.cleaned_data["last_name"]
                user.username = form.cleaned_data["generated_username"]
                user.email = form.cleaned_data["email"]
                user.is_active = False
                user.set_password(form.cleaned_data["password1"])
                user.save()

                UserProfile.objects.create(
                    user=user,
                    email_verified=False,
                    admin_approved=False,
                )
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
                f"Impossible d'envoyer le mail de confirmation : {exc}",
            )

    return render(request, "app_accounts/register.html", {"form": form})


@require_http_methods(["GET", "POST"])
def resend_verification_view(request):
    """Renvoie l'email de vérification pour un compte dont l'adresse n'a pas encore été confirmée."""
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
    """Marque l'email comme vérifié via le jeton reçu dans le lien de confirmation."""
    token_obj = get_object_or_404(EmailVerificationToken, token=token)
    user = token_obj.user
    profile, _ = UserProfile.objects.get_or_create(user=user)

    if token_obj.is_used:
        return render(
            request,
            "app_accounts/email_verified.html",
            {
                "already_used": True,
                "admin_approved": profile.admin_approved,
            },
        )

    if token_obj.is_expired():
        return render(request, "app_accounts/email_verification_invalid.html")

    profile.email_verified = True
    profile.save(update_fields=["email_verified"])
    sync_user_activation_state(user, profile=profile)

    token_obj.is_used = True
    token_obj.save(update_fields=["is_used"])

    return render(
        request,
        "app_accounts/email_verified.html",
        {
            "already_used": False,
            "admin_approved": profile.admin_approved,
        },
    )


def logout_view(request):
    """Déconnecte l'utilisateur et le redirige vers la page de connexion."""
    logout(request)
    messages.success(request, "Vous êtes maintenant déconnecté.")
    return redirect("accounts:login")


@login_required
@require_http_methods(["GET", "POST"])
def settings_view(request):
    """Affiche et traite les formulaires de mise à jour du profil et de changement de mot de passe."""
    profile_form = AccountSettingsForm(request.POST or None, instance=request.user, prefix="profile")
    password_form = AccountPasswordForm(user=request.user, data=request.POST or None, prefix="password")

    if request.method == "POST":
        form_type = request.POST.get("form_type")

        if form_type == "profile" and profile_form.is_valid():
            user = profile_form.save()
            messages.success(request, f"Profil mis à jour. Nouveau nom d'utilisateur : {user.username}")
            return redirect("accounts:settings")

        if form_type == "password" and password_form.is_valid():
            user = password_form.save()
            update_session_auth_hash(request, user)
            messages.success(request, "Mot de passe mis à jour.")
            return redirect("accounts:settings")

    return render(
        request,
        "app_accounts/settings.html",
        {
            "profile_form": profile_form,
            "password_form": password_form,
        },
    )
