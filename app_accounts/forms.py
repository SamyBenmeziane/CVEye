from django import forms
from django.contrib.auth.forms import PasswordChangeForm, SetPasswordForm
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from app_core.text_utils import clean_text_value
from .utils import generate_unique_username


class RegisterForm(forms.ModelForm):
    password1 = forms.CharField(
        label="Mot de passe",
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
    password2 = forms.CharField(
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

    class Meta:
        model = User
        fields = ["first_name", "last_name", "email"]
        labels = {
            "first_name": "Prenom",
            "last_name": "Nom",
            "email": "Email",
        }
        widgets = {
            "first_name": forms.TextInput(
                attrs={
                    "maxlength": 150,
                    "autocomplete": "given-name",
                    "spellcheck": "false",
                    "autocapitalize": "words",
                    "autofocus": True,
                }
            ),
            "last_name": forms.TextInput(
                attrs={
                    "maxlength": 150,
                    "autocomplete": "family-name",
                    "spellcheck": "false",
                    "autocapitalize": "words",
                }
            ),
            "email": forms.EmailInput(
                attrs={
                    "maxlength": 254,
                    "autocomplete": "email",
                    "autocapitalize": "none",
                    "spellcheck": "false",
                    "inputmode": "email",
                }
            ),
        }

    def clean_first_name(self):
        """Nettoie et valide le prénom en supprimant les balises HTML.

        Lève ValidationError si la valeur est vide après nettoyage.
        """
        value = clean_text_value(self.cleaned_data.get("first_name"), max_length=150)
        if not value:
            raise ValidationError("Ce champ est obligatoire.")
        return value

    def clean_last_name(self):
        """Nettoie et valide le nom de famille en supprimant les balises HTML.

        Lève ValidationError si la valeur est vide après nettoyage.
        """
        value = clean_text_value(self.cleaned_data.get("last_name"), max_length=150)
        if not value:
            raise ValidationError("Ce champ est obligatoire.")
        return value

    def clean_email(self):
        """Nettoie, normalise en minuscules et vérifie l'unicité de l'adresse email.

        Lève ValidationError si l'email est vide ou déjà utilisé par un autre compte.
        """
        email = clean_text_value(self.cleaned_data.get("email"), lower=True, max_length=254)
        if not email:
            raise ValidationError("Ce champ est obligatoire.")
        if User.objects.filter(email=email).exists():
            raise ValidationError("Cet email est deja utilise.")
        return email

    def clean_password1(self):
        """Valide le mot de passe selon les règles de sécurité Django configurées.

        Lève ValidationError si le mot de passe est vide ou ne respecte pas les règles.
        """
        password = self.cleaned_data.get("password1")
        if not password:
            raise ValidationError("Ce champ est obligatoire.")
        validate_password(password, self.instance)
        return password

    def clean(self):
        """Valide le formulaire globalement : vérifie la correspondance des mots de passe
        et génère le nom d'utilisateur unique à partir du prénom et du nom."""
        cleaned_data = super().clean()
        p1 = cleaned_data.get("password1")
        p2 = cleaned_data.get("password2")
        if p1 and p2 and p1 != p2:
            raise ValidationError("Les mots de passe ne correspondent pas.")

        first_name = cleaned_data.get("first_name")
        last_name = cleaned_data.get("last_name")
        # Le nom utilisateur est prepare ici pour rester coherent avec le prenom et le nom
        if first_name and last_name:
            cleaned_data["generated_username"] = generate_unique_username(first_name, last_name)

        return cleaned_data


class LoginForm(forms.Form):
    username = forms.CharField(
        max_length=150,
        label="Nom d'utilisateur",
        widget=forms.TextInput(
            attrs={
                "maxlength": 150,
                "autocomplete": "username",
                "spellcheck": "false",
                "autocapitalize": "none",
                "autofocus": True,
            }
        ),
    )
    password = forms.CharField(
        label="Mot de passe",
        strip=False,
        max_length=128,
        widget=forms.PasswordInput(
            attrs={
                "autocomplete": "current-password",
                "maxlength": 128,
            },
            render_value=False,
        ),
    )

    def clean_username(self):
        """Nettoie le nom d'utilisateur et vérifie qu'il n'est pas vide."""
        username = clean_text_value(self.cleaned_data.get("username"), max_length=150)
        if not username:
            raise ValidationError("Ce champ est obligatoire.")
        return username

    def clean_password(self):
        """Vérifie que le champ mot de passe n'est pas vide."""
        password = self.cleaned_data.get("password")
        if not password:
            raise ValidationError("Ce champ est obligatoire.")
        return password


class PasswordResetRequestForm(forms.Form):
    username = forms.CharField(
        label="Nom d'utilisateur",
        max_length=150,
        widget=forms.TextInput(
            attrs={
                "maxlength": 150,
                "autocomplete": "username",
                "spellcheck": "false",
                "autocapitalize": "none",
                "autofocus": True,
            }
        ),
    )
    email = forms.EmailField(
        label="Email",
        max_length=254,
        widget=forms.EmailInput(
            attrs={
                "maxlength": 254,
                "autocomplete": "email",
                "autocapitalize": "none",
                "spellcheck": "false",
                "inputmode": "email",
                "autofocus": True,
            }
        ),
    )

    def clean_username(self):
        """Nettoie et normalise le nom d'utilisateur pour la recherche du compte."""
        username = clean_text_value(self.cleaned_data.get("username"), max_length=150)
        if not username:
            raise ValidationError("Ce champ est obligatoire.")
        return username

    def clean_email(self):
        """Nettoie et normalise en minuscules l'email pour la recherche du compte."""
        email = clean_text_value(self.cleaned_data.get("email"), lower=True, max_length=254)
        if not email:
            raise ValidationError("Ce champ est obligatoire.")
        return email


class AccountSettingsForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ["first_name", "last_name"]
        labels = {
            "first_name": "Prenom",
            "last_name": "Nom",
        }
        widgets = {
            "first_name": forms.TextInput(
                attrs={
                    "maxlength": 150,
                    "autocomplete": "given-name",
                    "spellcheck": "false",
                    "autocapitalize": "words",
                }
            ),
            "last_name": forms.TextInput(
                attrs={
                    "maxlength": 150,
                    "autocomplete": "family-name",
                    "spellcheck": "false",
                    "autocapitalize": "words",
                }
            ),
        }

    def clean_first_name(self):
        """Nettoie le prénom et lève ValidationError s'il est vide après nettoyage."""
        value = clean_text_value(self.cleaned_data.get("first_name"), max_length=150)
        if not value:
            raise ValidationError("Ce champ est obligatoire.")
        return value

    def clean_last_name(self):
        """Nettoie le nom de famille et lève ValidationError s'il est vide après nettoyage."""
        value = clean_text_value(self.cleaned_data.get("last_name"), max_length=150)
        if not value:
            raise ValidationError("Ce champ est obligatoire.")
        return value

    def save(self, commit=True):
        """Sauvegarde le profil et recalcule le nom d'utilisateur depuis le prénom et le nom."""
        user = super().save(commit=False)
        user.username = generate_unique_username(
            user.first_name,
            user.last_name,
            exclude_user_id=user.pk,
        )

        if commit:
            user.save()

        return user


class AccountPasswordForm(PasswordChangeForm):
    old_password = forms.CharField(
        label="Mot de passe actuel",
        strip=False,
        max_length=128,
        widget=forms.PasswordInput(
            attrs={
                "autocomplete": "current-password",
                "maxlength": 128,
            },
            render_value=False,
        ),
    )
    new_password1 = forms.CharField(
        label="Nouveau mot de passe",
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
    new_password2 = forms.CharField(
        label="Confirmer le nouveau mot de passe",
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


class PasswordResetConfirmForm(SetPasswordForm):
    new_password1 = forms.CharField(
        label="Nouveau mot de passe",
        strip=False,
        max_length=128,
        widget=forms.PasswordInput(
            attrs={
                "autocomplete": "new-password",
                "maxlength": 128,
                "autofocus": True,
            },
            render_value=False,
        ),
    )
    new_password2 = forms.CharField(
        label="Confirmer le nouveau mot de passe",
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
