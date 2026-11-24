from django.test import TestCase
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db import IntegrityError

from app_core.models import Cible, InstallationConfig
from app_core.text_utils import clean_text_value


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


class CleanTextValueTest(TestCase):
    """Tests pour la fonction utilitaire clean_text_value."""

    def test_supprime_les_balises_html(self):
        """clean_text_value doit retirer les balises HTML pour eviter du XSS stocke"""
        # strip_tags retire les balises mais garde le texte qui etait dedans
        self.assertEqual(clean_text_value("<b>texte</b>"), "texte")
        self.assertEqual(clean_text_value("<p>hello <span>world</span></p>"), "hello world")

    def test_supprime_les_espaces_en_debut_et_fin(self):
        """clean_text_value doit appliquer un strip sur les espaces"""
        self.assertEqual(clean_text_value("   coucou   "), "coucou")

    def test_retourne_chaine_vide_si_none(self):
        """clean_text_value doit retourner une chaine vide quand la valeur est None"""
        self.assertEqual(clean_text_value(None), "")

    def test_option_lower_met_en_minuscules(self):
        """clean_text_value avec lower=True doit normaliser en minuscules"""
        self.assertEqual(clean_text_value("ALICE@EXAMPLE.COM", lower=True), "alice@example.com")

    def test_option_max_length_tronque(self):
        """clean_text_value avec max_length doit tronquer la chaine"""
        self.assertEqual(clean_text_value("abcdefghij", max_length=5), "abcde")

    def test_combine_lower_et_max_length(self):
        """clean_text_value doit pouvoir combiner les deux options"""
        self.assertEqual(
            clean_text_value("  HELLO WORLD  ", lower=True, max_length=5),
            "hello",
        )


class InstallationConfigTest(TestCase):
    """Tests pour le modele singleton InstallationConfig."""

    def test_load_cree_la_config_si_absente(self):
        """load() doit creer la config si elle n'existe pas encore"""
        InstallationConfig.objects.all().delete()

        config = InstallationConfig.load()

        self.assertIsNotNone(config.pk)
        self.assertFalse(config.is_installed)

    def test_load_est_idempotent(self):
        """load() appele plusieurs fois doit retourner la meme instance (pk=1)"""
        InstallationConfig.objects.all().delete()

        config1 = InstallationConfig.load()
        config2 = InstallationConfig.load()

        self.assertEqual(config1.pk, config2.pk)
        self.assertEqual(InstallationConfig.objects.count(), 1)