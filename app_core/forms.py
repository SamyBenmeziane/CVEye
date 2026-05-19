from django import forms
from app_core.text_utils import clean_text_value


class InstallationForm(forms.Form):
    site_name = forms.CharField(
        max_length=150,
        required=True,
        initial="CVEye",
        label="Nom du site",
        widget=forms.TextInput(
            attrs={
                "maxlength": 150,
                "autocomplete": "organization",
                "spellcheck": "false",
            }
        ),
    )

    admin_first_name = forms.CharField(
        max_length=150,
        required=True,
        label="Prenom administrateur",
        widget=forms.TextInput(
            attrs={
                "maxlength": 150,
                "autocomplete": "given-name",
                "spellcheck": "false",
                "autocapitalize": "words",
            }
        ),
    )

    admin_last_name = forms.CharField(
        max_length=150,
        required=True,
        label="Nom administrateur",
        widget=forms.TextInput(
            attrs={
                "maxlength": 150,
                "autocomplete": "family-name",
                "spellcheck": "false",
                "autocapitalize": "words",
            }
        ),
    )

    admin_email = forms.EmailField(
        required=True,
        label="Email administrateur",
        widget=forms.EmailInput(
            attrs={
                "maxlength": 254,
                "autocomplete": "email",
                "autocapitalize": "none",
                "spellcheck": "false",
                "inputmode": "email",
            }
        ),
    )

    admin_password = forms.CharField(
        required=True,
        label="Mot de passe administrateur",
        strip=False,
        max_length=128,
        widget=forms.PasswordInput(
            attrs={
                "autocomplete": "new-password",
                "maxlength": 128,
            },
            render_value=False,
        ),
    )

    admin_password_confirm = forms.CharField(
        required=True,
        label="Confirmation du mot de passe",
        strip=False,
        max_length=128,
        widget=forms.PasswordInput(
            attrs={
                "autocomplete": "new-password",
                "maxlength": 128,
            },
            render_value=False,
        ),
    )

    smtp_host = forms.CharField(
        max_length=255,
        required=False,
        label="SMTP Host",
        widget=forms.TextInput(
            attrs={
                "maxlength": 255,
                "autocomplete": "off",
                "autocapitalize": "none",
                "spellcheck": "false",
            }
        ),
    )

    smtp_port = forms.IntegerField(
        required=False,
        initial=587,
        min_value=1,
        max_value=65535,
        label="SMTP Port",
        widget=forms.NumberInput(
            attrs={
                "min": 1,
                "max": 65535,
                "inputmode": "numeric",
                "autocomplete": "off",
            }
        ),
    )

    smtp_username = forms.CharField(
        max_length=255,
        required=False,
        label="SMTP Username",
        widget=forms.TextInput(
            attrs={
                "maxlength": 255,
                "autocomplete": "username",
                "autocapitalize": "none",
                "spellcheck": "false",
            }
        ),
    )

    smtp_password = forms.CharField(
        required=False,
        label="SMTP Password",
        strip=False,
        max_length=128,
        widget=forms.PasswordInput(
            attrs={
                "autocomplete": "new-password",
                "maxlength": 128,
            },
            render_value=False,
        ),
    )

    smtp_from_email = forms.EmailField(
        required=False,
        label="Email expediteur",
        widget=forms.EmailInput(
            attrs={
                "maxlength": 254,
                "autocomplete": "email",
                "autocapitalize": "none",
                "spellcheck": "false",
                "inputmode": "email",
            }
        ),
    )

    smtp_use_tls = forms.BooleanField(
        required=False,
        initial=True,
        label="Utiliser TLS"
    )

    smtp_use_ssl = forms.BooleanField(
        required=False,
        initial=False,
        label="Utiliser SSL"
    )

    def clean_site_name(self):
        """Nettoie le nom du site et lève ValidationError s'il est vide après nettoyage."""
        value = clean_text_value(self.cleaned_data.get("site_name"), max_length=150)
        if not value:
            raise forms.ValidationError("Ce champ est obligatoire.")
        return value

    def clean_admin_email(self):
        """Nettoie et normalise en minuscules l'email de l'administrateur."""
        value = clean_text_value(self.cleaned_data.get("admin_email"), lower=True, max_length=254)
        if not value:
            raise forms.ValidationError("Ce champ est obligatoire.")
        return value

    def clean_admin_first_name(self):
        """Nettoie le prénom de l'administrateur et lève ValidationError s'il est vide."""
        value = clean_text_value(self.cleaned_data.get("admin_first_name"), max_length=150)
        if not value:
            raise forms.ValidationError("Ce champ est obligatoire.")
        return value

    def clean_admin_last_name(self):
        """Nettoie le nom de famille de l'administrateur et lève ValidationError s'il est vide."""
        value = clean_text_value(self.cleaned_data.get("admin_last_name"), max_length=150)
        if not value:
            raise forms.ValidationError("Ce champ est obligatoire.")
        return value

    def clean_smtp_host(self):
        """Nettoie et met en minuscules le nom d'hôte SMTP."""
        return clean_text_value(self.cleaned_data.get("smtp_host"), lower=True, max_length=255)

    def clean_smtp_username(self):
        """Nettoie le nom d'utilisateur SMTP."""
        return clean_text_value(self.cleaned_data.get("smtp_username"), max_length=255)

    def clean_smtp_from_email(self):
        """Nettoie et normalise en minuscules l'adresse email expéditrice SMTP."""
        return clean_text_value(self.cleaned_data.get("smtp_from_email"), lower=True, max_length=254)

    def clean(self):
        """Valide globalement le formulaire : vérifie la correspondance des mots de passe administrateur."""
        cleaned_data = super().clean()

        admin_password = cleaned_data.get("admin_password")
        admin_password_confirm = cleaned_data.get("admin_password_confirm")

        if admin_password and admin_password_confirm and admin_password != admin_password_confirm:
            raise forms.ValidationError("Les mots de passe administrateur ne correspondent pas.")

        return cleaned_data
