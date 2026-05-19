import ipaddress
import re

from django import forms
from django.utils.html import strip_tags

from app_core.models import Cible


DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


class TargetForm(forms.ModelForm):
    class Meta:
        model = Cible
        fields = [
            "adresse",
            "type_cible",
            "description",
            "active",
            "surveillance_active",
            "periodicite_scan",
        ]
        widgets = {
            "adresse": forms.TextInput(
                attrs={
                    "placeholder": "Ex: 192.168.1.10 ou example.com",
                    "maxlength": 80,
                }
            ),
            "type_cible": forms.Select(),
            "description": forms.TextInput(
                attrs={
                    "placeholder": "Description optionnelle",
                    "maxlength": 255,
                }
            ),
            "periodicite_scan": forms.Select(),
        }

    def __init__(self, *args, **kwargs):
        """Initialise le formulaire et extrait l'utilisateur courant depuis kwargs."""
        self.user = kwargs.pop("user", None)
        super().__init__(*args, **kwargs)
        self.fields["adresse"].max_length = 80
        self.fields["description"].max_length = 255

    def clean_adresse(self):
        """Vérifie que le champ adresse n'est pas vide après nettoyage des espaces."""
        valeur = (self.cleaned_data.get("adresse") or "").strip()
        if not valeur:
            raise forms.ValidationError("Ce champ est obligatoire.")
        return valeur

    def clean_description(self):
        """Supprime les balises HTML de la description et tronque à 255 caractères."""
        valeur = self.cleaned_data.get("description")

        if valeur is None:
            return ""

        valeur = strip_tags(str(valeur)).strip()

        if not valeur:
            return ""

        return valeur[:255]

    def clean(self):
        """Valide le format de l'adresse, l'unicité par utilisateur et la cohérence de la surveillance."""
        cleaned_data = super().clean()
        adresse = (cleaned_data.get("adresse") or "").strip()
        type_cible = cleaned_data.get("type_cible")
        surveillance_active = cleaned_data.get("surveillance_active")
        periodicite_scan = cleaned_data.get("periodicite_scan")

        if adresse and type_cible == "ip":
            try:
                ipaddress.ip_address(adresse)
            except ValueError:
                self.add_error("adresse", "Adresse IP invalide.")

        elif adresse and type_cible == "domaine":
            # On repasse le domaine en minuscule pour garder une seule version de la meme cible
            adresse_normalisee = adresse.rstrip(".").lower()

            if not adresse_normalisee:
                self.add_error("adresse", "Nom de domaine invalide.")
            elif "://" in adresse_normalisee or ":" in adresse_normalisee or any(
                char.isspace() for char in adresse_normalisee
            ):
                self.add_error("adresse", "Nom de domaine invalide.")
            else:
                try:
                    ipaddress.ip_address(adresse_normalisee)
                except ValueError:
                    pass
                else:
                    self.add_error("adresse", "Veuillez saisir un nom de domaine valide.")

                if "adresse" not in self.errors and not DOMAIN_REGEX.match(adresse_normalisee):
                    self.add_error("adresse", "Nom de domaine invalide.")

            if "adresse" not in self.errors:
                cleaned_data["adresse"] = adresse_normalisee

        adresse_finale = cleaned_data.get("adresse")
        if adresse_finale and "adresse" not in self.errors:
            qs = Cible.objects.filter(owner=self.user, adresse=adresse_finale) if self.user else Cible.objects.none()

            if self.instance and self.instance.pk:
                qs = qs.exclude(pk=self.instance.pk)

            # On cherche les doublons seulement chez lutilisateur courant
            if self.user and qs.exists():
                self.add_error("adresse", "Vous avez deja ajoute cette cible.")

        if surveillance_active and not periodicite_scan:
            self.add_error(
                "periodicite_scan",
                "Veuillez choisir une periodicite si la surveillance est activee.",
            )

        if not surveillance_active:
            cleaned_data["periodicite_scan"] = None

        return cleaned_data
