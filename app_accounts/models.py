from django.conf import settings
from django.db import models
from django.utils import timezone
import uuid


class UserProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    email_verified = models.BooleanField(default=False)

    def __str__(self):
        return f"Profil de {self.user.username}"


class EmailVerificationToken(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)

    def is_expired(self):
        return timezone.now() > self.created_at + timezone.timedelta(hours=24)

    def __str__(self):
        return f"{self.user.username} - {self.token}"


class LoginAttempt(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    attempt_count = models.PositiveIntegerField(default=0)
    last_username = models.CharField(max_length=150, blank=True, default="")
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.ip_address} - {self.attempt_count}"


class BannedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=255, default="3 tentatives de connexion invalides")
    banned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip_address