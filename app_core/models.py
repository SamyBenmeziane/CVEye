import ipaddress
import re
import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


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
        """Retourne un résumé de la configuration pour l'interface d'administration."""
        return f"Installation Config - Installed={self.is_installed}"

    @classmethod
    def load(cls):
        """Récupère la configuration unique du site (pk=1), ou la crée si elle n'existe pas encore."""
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj


class Cible(models.Model):
    TYPE_CHOICES = [
        ("ip", "IP"),
        ("domaine", "Domaine"),
    ]

    PERIODICITE_CHOICES = [
        ("toutes_les_heures", "Toutes les heures"),
        ("tous_les_jours", "Tous les jours"),
        ("toutes_les_semaines", "Toutes les semaines"),
        ("tous_les_mois", "Tous les mois"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="owned_targets",
        blank=True,
        null=True,
    )
    adresse = models.CharField(max_length=80)
    type_cible = models.CharField(max_length=20, choices=TYPE_CHOICES, default="ip")
    description = models.CharField(max_length=255, blank=True, null=True)
    active = models.BooleanField(default=True)

    surveillance_active = models.BooleanField(default=False)
    periodicite_scan = models.CharField(
        max_length=40,
        choices=PERIODICITE_CHOICES,
        blank=True,
        null=True,
    )
    dernier_scan_le = models.DateTimeField(blank=True, null=True)
    prochain_scan_le = models.DateTimeField(blank=True, null=True)

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
        """Retourne l'adresse de la cible."""
        return self.adresse

    def clean(self):
        """Valide et normalise la cible avant enregistrement.

        Vérifie le format de l'adresse IP ou du domaine, normalise le domaine en minuscules
        et contrôle la cohérence entre la surveillance active et la périodicité.
        Lève ValidationError si une règle n'est pas respectée.
        """
        errors = {}
        adresse = (self.adresse or "").strip()

        if not adresse:
            errors["adresse"] = "Ce champ est obligatoire."
        elif len(adresse) > 80:
            errors["adresse"] = "L adresse ne doit pas depasser 80 caracteres."
        elif self.type_cible == "ip":
            try:
                ipaddress.ip_address(adresse)
            except ValueError:
                errors["adresse"] = "Adresse IP invalide."
        # On normalise le domaine pour eviter les doublons a cause de la casse ou du point final
        elif self.type_cible == "domaine":
            adresse_normalisee = adresse.rstrip(".").lower()

            if not adresse_normalisee:
                errors["adresse"] = "Nom de domaine invalide."
            elif "://" in adresse_normalisee or ":" in adresse_normalisee or any(
                char.isspace() for char in adresse_normalisee
            ):
                errors["adresse"] = "Nom de domaine invalide."
            else:
                try:
                    ipaddress.ip_address(adresse_normalisee)
                except ValueError:
                    pass
                else:
                    errors["adresse"] = "Veuillez saisir un nom de domaine valide."

                if "adresse" not in errors and not DOMAIN_REGEX.match(adresse_normalisee):
                    errors["adresse"] = "Nom de domaine invalide."

            adresse = adresse_normalisee

        self.adresse = adresse

        if self.surveillance_active and not self.periodicite_scan:
            errors["periodicite_scan"] = "Veuillez choisir une periodicite si la surveillance est activee."

        if not self.surveillance_active:
            self.periodicite_scan = None

        if errors:
            raise ValidationError(errors)


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
    ports_scannes_courant = models.PositiveIntegerField(default=0)
    ports_ouverts = models.PositiveIntegerField(default=0)
    version_scanner = models.CharField(max_length=50, default="SocketScanner")
    message_erreur = models.TextField(blank=True, null=True)
    server_hs = models.BooleanField(default=False)

    class Meta:
        db_table = "scan"
        ordering = ["-date_debut"]

    def __str__(self):
        """Retourne un résumé du scan avec son identifiant et l'adresse de la cible associée."""
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
        """Retourne le nom du service avec son port et son protocole."""
        return f"{self.nom_service} ({self.port}/{self.protocole})"
