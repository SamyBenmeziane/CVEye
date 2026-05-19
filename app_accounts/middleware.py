from django.contrib import messages
from django.contrib.auth import logout
from django.http import HttpResponseForbidden
from django.shortcuts import redirect

from .models import BannedIP, UserProfile
from .utils import get_client_ip, sync_user_activation_state


class IPBanMiddleware:
    EXCLUDED_PREFIXES = ["/static/", "/media/"]

    def __init__(self, get_response):
        """Initialise le middleware avec la fonction de traitement suivante dans la chaîne."""
        self.get_response = get_response

    def __call__(self, request):
        """Intercepte la requête et retourne 403 si l'adresse IP du client est bannie.

        Les chemins statiques et médias sont exemptés de la vérification.
        """
        path = request.path

        for prefix in self.EXCLUDED_PREFIXES:
            if path.startswith(prefix):
                return self.get_response(request)

        ip_address = get_client_ip(request)

        if ip_address and BannedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden(
                "<h1>403 - Acces interdit</h1>"
                "<p>Contactez l administrateur.</p>"
            )

        return self.get_response(request)


class AccountStatusMiddleware:
    EXCLUDED_PREFIXES = [
        "/static/",
        "/media/",
        "/login/",
        "/register/",
        "/verify-email/",
        "/resend-verification/",
    ]

    def __init__(self, get_response):
        """Initialise le middleware avec la fonction de traitement suivante dans la chaîne."""
        self.get_response = get_response

    def __call__(self, request):
        """Vérifie l'état du compte à chaque requête et force la déconnexion si nécessaire.

        Contrôle la vérification de l'email, l'approbation et l'état de désactivation.
        Les super administrateurs et les pages publiques (connexion, inscription) sont exemptés.
        """
        if not request.user.is_authenticated:
            return self.get_response(request)

        if any(request.path.startswith(prefix) for prefix in self.EXCLUDED_PREFIXES):
            return self.get_response(request)

        profile, _ = UserProfile.objects.get_or_create(user=request.user)
        sync_user_activation_state(request.user, profile=profile)

        if request.user.is_superuser:
            return self.get_response(request)

        logout_reason = None
        if not profile.email_verified:
            logout_reason = "Vous devez confirmer votre adresse email avant de continuer."
        elif not profile.admin_approved:
            logout_reason = "Votre compte est en attente de validation par un administrateur."
        elif profile.admin_disabled:
            logout_reason = "Votre compte a ete desactive par un administrateur."
        elif not request.user.is_active:
            logout_reason = "Votre compte a ete desactive."

        if logout_reason:
            logout(request)
            messages.error(request, logout_reason)
            return redirect("accounts:login")

        return self.get_response(request)
