from django import forms
from app_core.models import Cible
import ipaddress


class TargetForm(forms.ModelForm):
    class Meta:
        model = Cible
        fields = ["adresse", "type_cible", "description", "active"]
        widgets = {
            "adresse": forms.TextInput(attrs={"placeholder": "Ex: 192.168.1.10 ou example.com"}),
            "type_cible": forms.Select(),
            "description": forms.TextInput(attrs={"placeholder": "Description optionnelle"}),
        }

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user", None)
        super().__init__(*args, **kwargs)

    def clean_adresse(self):
        valeur = self.cleaned_data["adresse"].strip()
        type_cible = self.cleaned_data.get("type_cible")

        if type_cible == "ip":
            try:
                ipaddress.ip_address(valeur)
            except ValueError:
                raise forms.ValidationError("Adresse IP invalide.")

        if self.user and Cible.objects.filter(owner=self.user, adresse=valeur).exists():
            raise forms.ValidationError("Vous avez déjà ajouté cette cible.")

        return valeur