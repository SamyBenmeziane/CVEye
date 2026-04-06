import uuid

from django.conf import settings
from django.db import models


class InstallationConfig(models.Model):
    is_installed = models.BooleanField(default=False)
    installed_at = models.DateTimeField(blank=True, null=True)

    site_name = models.CharField(max_length=150, default="CVEye", blank=True)
    smtp_host = models.CharField(max_length=255, default="", blank=True)
    smtp_port = models.PositiveIntegerField(default=587)
    smtp_username = models.CharField(max_length=255, default="", blank=True)
    smtp_password = models.CharField(max_length=255, default="", blank=True)
    smtp_use_tls = models.BooleanField(default=True)
    smtp_use_ssl = models.BooleanField(default=False)
    smtp_from_email = models.EmailField(default="", blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Installation Configuration"
        verbose_name_plural = "Installation Configuration"
        db_table = "installation_config"

    def __str__(self):
        return f"Installation Config - Installed={self.is_installed}"

    @classmethod
    def load(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj


class Cible(models.Model):
    TYPE_CHOICES = [
        ("ip", "IP"),
        ("domaine", "Domaine"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="owned_targets",
        blank=True,
        null=True,
    )
    adresse = models.CharField(max_length=255)
    type_cible = models.CharField(max_length=20, choices=TYPE_CHOICES, default="ip")
    description = models.CharField(max_length=255, blank=True, null=True)
    active = models.BooleanField(default=True)
    date_creation = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "cible"
        ordering = ["adresse"]
        constraints = [
            models.UniqueConstraint(
                fields=["owner", "adresse"],
                name="unique_target_per_user"
            )
        ]

    def __str__(self):
        return self.adresse


class Scan(models.Model):
    STATUT_CHOICES = [
        ("en_attente", "En attente"),
        ("en_cours", "En cours"),
        ("complete", "Complete"),
        ("echoue", "Echoue"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    cible = models.ForeignKey(Cible, on_delete=models.CASCADE, related_name="scans")
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="owned_scans",
        blank=True,
        null=True,
    )
    date_debut = models.DateTimeField(auto_now_add=True)
    date_fin = models.DateTimeField(blank=True, null=True)
    statut = models.CharField(max_length=20, choices=STATUT_CHOICES, default="en_attente")
    ports_scannes = models.PositiveIntegerField(default=65535)
    ports_ouverts = models.PositiveIntegerField(default=0)
    version_scanner = models.CharField(max_length=50, default="SocketScanner")
    message_erreur = models.TextField(blank=True, null=True)

    class Meta:
        db_table = "scan"
        ordering = ["-date_debut"]

    def __str__(self):
        return f"Scan {self.id} - {self.cible.adresse}"


class Service(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="services")
    port = models.PositiveIntegerField()
    protocole = models.CharField(max_length=10, default="tcp")
    nom_service = models.CharField(max_length=100, default="unknown")
    produit = models.CharField(max_length=255, blank=True, null=True)
    version = models.CharField(max_length=100, blank=True, null=True)
    banniere = models.TextField(blank=True, null=True)
    en_tetes = models.JSONField(blank=True, default=dict)
    etat = models.CharField(max_length=20, default="open")
    date_detection = models.DateTimeField(auto_now_add=True)
    cpe_match_string = models.CharField(max_length=255, blank=True, null=True)
    cpe_name = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        db_table = "service"
        ordering = ["port"]
        unique_together = ("scan", "port", "protocole")

    def __str__(self):
        return f"{self.nom_service} ({self.port}/{self.protocole})"