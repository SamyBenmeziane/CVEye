from django.test import TestCase
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db import IntegrityError

from app_core.models import Cible


class CibleTest(TestCase):

    def test_creation_cible(self):
        user = User.objects.create_user(
            username="testuser_core",
            password="testpass123"
        )

        cible = Cible.objects.create(
            owner=user,
            adresse="192.168.1.1"
        )

        self.assertEqual(cible.owner.username, "testuser_core")
        self.assertEqual(cible.adresse, "192.168.1.1")

    def test_unique_cible_per_user(self):
        user = User.objects.create_user(
            username="user_core_unique",
            password="testpass123"
        )

        Cible.objects.create(
            owner=user,
            adresse="192.168.1.1"
        )

        with self.assertRaises(IntegrityError):
            Cible.objects.create(
                owner=user,
                adresse="192.168.1.1"
            )

    def test_clean_rejette_ip_invalide(self):
        """clean() doit lever ValidationError pour une IP invalide"""
        cible = Cible(adresse="999.999.999.999", type_cible="ip")

        with self.assertRaises(ValidationError) as ctx:
            cible.clean()

        self.assertIn("adresse", ctx.exception.message_dict)

    def test_clean_accepte_domaine_valide(self):
        """clean() doit accepter un nom de domaine valide sans lever d'erreur"""
        cible = Cible(adresse="exemple.fr", type_cible="domaine")

        # Ne doit pas lever d'exception
        cible.clean()

        self.assertEqual(cible.adresse, "exemple.fr")

    def test_clean_rejette_domaine_avec_espace(self):
        """clean() doit lever ValidationError pour un domaine contenant un espace"""
        cible = Cible(adresse="mauvais domaine.fr", type_cible="domaine")

        with self.assertRaises(ValidationError) as ctx:
            cible.clean()

        self.assertIn("adresse", ctx.exception.message_dict)