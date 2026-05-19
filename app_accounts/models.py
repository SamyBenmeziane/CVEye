from django.conf import settings
from django.db import models
from django.utils import timezone
import uuid


class UserProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    email_verified = models.BooleanField(default=False)
    admin_approved = models.BooleanField(default=False)
    admin_disabled = models.BooleanField(default=False)
    approved_at = models.DateTimeField(blank=True, null=True)
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="approved_accounts",
        blank=True,
        null=True,
    )
    disabled_at = models.DateTimeField(blank=True, null=True)
    disabled_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="disabled_accounts",
        blank=True,
        null=True,
    )

    @property
    def is_superadmin(self):
        """Indique si l'utilisateur associé à ce profil est un super administrateur Django."""
        return bool(self.user.is_superuser)

    def can_login(self):
        """Indique si le compte est autorisé à se connecter.

        Un super administrateur peut toujours se connecter.
        Pour les autres, les trois conditions doivent être réunies :
        email vérifié, compte approuvé par un administrateur, et non désactivé.
        """
        if self.is_superadmin:
            return True
        return self.email_verified and self.admin_approved and not self.admin_disabled

    def __str__(self):
        """Retourne la représentation textuelle du profil pour l'interface d'administration."""
        return f"Profil de {self.user.username}"


class EmailVerificationToken(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)

    def is_expired(self):
        """Indique si le jeton a dépassé sa durée de validité de 24 heures."""
        return timezone.now() > self.created_at + timezone.timedelta(hours=24)

    def __str__(self):
        """Retourne une représentation courte du jeton avec le nom d'utilisateur associé."""
        return f"{self.user.username} - {self.token}"


class LoginAttempt(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    attempt_count = models.PositiveIntegerField(default=0)
    last_username = models.CharField(max_length=150, blank=True, default="")
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        """Retourne un résumé de l'adresse IP et du nombre de tentatives échouées."""
        return f"{self.ip_address} - {self.attempt_count}"


class BannedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=255, default="3 tentatives de connexion invalides")
    banned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        """Retourne l'adresse IP bannie."""
        return self.ip_address
