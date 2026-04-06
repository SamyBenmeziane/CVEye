from django import forms


class InstallationForm(forms.Form):
    site_name = forms.CharField(
        max_length=150,
        required=True,
        initial="CVEye",
        label="Nom du site"
    )

    admin_email = forms.EmailField(
        required=True,
        label="Email administrateur"
    )

    admin_password = forms.CharField(
        widget=forms.PasswordInput,
        required=True,
        label="Mot de passe administrateur"
    )

    admin_password_confirm = forms.CharField(
        widget=forms.PasswordInput,
        required=True,
        label="Confirmation du mot de passe"
    )

    smtp_host = forms.CharField(
        max_length=255,
        required=False,
        label="SMTP Host"
    )

    smtp_port = forms.IntegerField(
        required=False,
        initial=587,
        label="SMTP Port"
    )

    smtp_username = forms.CharField(
        max_length=255,
        required=False,
        label="SMTP Username"
    )

    smtp_password = forms.CharField(
        widget=forms.PasswordInput,
        required=False,
        label="SMTP Password"
    )

    smtp_from_email = forms.EmailField(
        required=False,
        label="Email expéditeur"
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

    def clean(self):
        cleaned_data = super().clean()

        admin_password = cleaned_data.get("admin_password")
        admin_password_confirm = cleaned_data.get("admin_password_confirm")

        if admin_password and admin_password_confirm and admin_password != admin_password_confirm:
            raise forms.ValidationError("Les mots de passe administrateur ne correspondent pas.")

        return cleaned_data