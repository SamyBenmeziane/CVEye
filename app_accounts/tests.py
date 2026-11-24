from django.test import RequestFactory, TestCase
from django.contrib.auth.models import User
from django.db import IntegrityError

from app_accounts.models import BannedIP, LoginAttempt, UserProfile
from app_accounts.utils import (
    build_username_base,
    generate_unique_username,
    get_client_ip,
    is_ip_banned,
    register_failed_attempt,
    reset_attempts,
    sync_user_activation_state,
)
from django.urls import reverse


class RegisterFailedAttemptTest(TestCase):

    def test_pas_de_ban_avant_3_tentatives(self):
        """Apres 1 ou 2 echecs, l'IP ne doit pas etre bannie"""
        ip = "203.0.113.10"

        result1 = register_failed_attempt(ip, username="alice")
        self.assertFalse(result1)
        self.assertFalse(BannedIP.objects.filter(ip_address=ip).exists())

        result2 = register_failed_attempt(ip, username="alice")
        self.assertFalse(result2)
        self.assertFalse(BannedIP.objects.filter(ip_address=ip).exists())

    def test_ban_au_3eme_echec(self):
        """Au 3eme echec, l'IP est bannie et le compteur est remis a zero"""
        ip = "203.0.113.20"

        register_failed_attempt(ip)
        register_failed_attempt(ip)
        result3 = register_failed_attempt(ip)

        self.assertTrue(result3)
        self.assertTrue(BannedIP.objects.filter(ip_address=ip).exists())
        # Le compteur doit etre supprime apres le ban
        self.assertFalse(LoginAttempt.objects.filter(ip_address=ip).exists())

    def test_ip_vide_ne_fait_rien(self):
        """Si l'IP est vide ou None, on retourne False sans rien creer"""
        self.assertFalse(register_failed_attempt(""))
        self.assertFalse(register_failed_attempt(None))
        self.assertEqual(LoginAttempt.objects.count(), 0)
        self.assertEqual(BannedIP.objects.count(), 0)


class IsIpBannedTest(TestCase):

    def test_retourne_true_pour_ip_bannie(self):
        """is_ip_banned doit retourner True si l'IP existe dans BannedIP"""
        BannedIP.objects.create(ip_address="198.51.100.7", reason="Test")
        self.assertTrue(is_ip_banned("198.51.100.7"))

    def test_retourne_false_pour_ip_non_bannie(self):
        """is_ip_banned doit retourner False pour une IP jamais vue"""
        self.assertFalse(is_ip_banned("198.51.100.99"))


class ResetAttemptsTest(TestCase):

    def test_efface_le_compteur_de_lip(self):
        """reset_attempts doit supprimer toutes les tentatives ratees enregistrees pour une IP"""
        ip = "203.0.113.50"

        # On simule 2 echecs
        register_failed_attempt(ip)
        register_failed_attempt(ip)
        self.assertTrue(LoginAttempt.objects.filter(ip_address=ip).exists())

        # Reset
        reset_attempts(ip)

        # Le compteur a ete efface
        self.assertFalse(LoginAttempt.objects.filter(ip_address=ip).exists())

    def test_ip_vide_ne_plante_pas(self):
        """reset_attempts avec une IP vide ne doit rien faire et ne pas planter"""
        reset_attempts("")
        reset_attempts(None)
        # Doit s'executer sans exception


class GetClientIpTest(TestCase):

    def setUp(self):
        self.factory = RequestFactory()

    def test_priorise_x_forwarded_for_si_present(self):
        """Si X-Forwarded-For est present, on prend la 1re IP de la liste"""
        request = self.factory.get("/")
        request.META["HTTP_X_FORWARDED_FOR"] = "203.0.113.5, 10.0.0.1"
        request.META["REMOTE_ADDR"] = "10.0.0.1"

        self.assertEqual(get_client_ip(request), "203.0.113.5")

    def test_fallback_sur_remote_addr_si_pas_de_header(self):
        """Sans X-Forwarded-For, on utilise REMOTE_ADDR"""
        request = self.factory.get("/")
        request.META["REMOTE_ADDR"] = "192.168.1.42"

        self.assertEqual(get_client_ip(request), "192.168.1.42")

    def test_chaine_vide_si_aucune_info(self):
        """Si rien n'est present, on retourne une chaine vide (jamais None)"""
        request = self.factory.get("/")
        request.META.pop("REMOTE_ADDR", None)

        self.assertEqual(get_client_ip(request), "")


class BuildUsernameBaseTest(TestCase):

    def test_normalise_accents_majuscules_et_espaces(self):
        """build_username_base doit produire un nom ASCII en minuscules avec un point comme separateur"""
        # Cas standard avec accents
        self.assertEqual(build_username_base("Jean", "Dupont"), "jean.dupont")

        # Accents (Francois -> francois) et trait d'union
        self.assertEqual(build_username_base("Jean-François", "Dupont"), "jean.francois.dupont")

        # Espaces multiples et majuscules
        self.assertEqual(build_username_base("Marie  Anne", "DE LA TOUR"), "marie.anne.de.la.tour")

        # Champ vide : ne plante pas, juste une partie
        self.assertEqual(build_username_base("", "Durand"), "durand")
        self.assertEqual(build_username_base("Alice", ""), "alice")


class UserProfileTest(TestCase):

    def test_creation_userprofile(self):
        user = User.objects.create_user(
            username="testuser",
            password="testpass123"
        )

        profile = UserProfile.objects.create(
            user=user,
            email_verified=False,
            admin_approved=False
        )

        self.assertEqual(profile.user.username, "testuser")
        self.assertFalse(profile.email_verified)
        self.assertFalse(profile.admin_approved)
        self.assertFalse(profile.can_login())

    def test_user_cannot_login_if_not_verified(self):
        user = User.objects.create_user(
            username="user2",
            password="testpass123"
        )

        profile = UserProfile.objects.create(
            user=user,
            email_verified=False,
            admin_approved=False
        )

        self.assertFalse(profile.can_login())

    def test_user_can_login_if_verified_and_approved(self):
        user = User.objects.create_user(
            username="user3",
            password="testpass123"
        )

        profile = UserProfile.objects.create(
            user=user,
            email_verified=True,
            admin_approved=True
        )

        self.assertTrue(profile.can_login())

    def test_one_profile_per_user(self):
        user = User.objects.create_user(
            username="user_unique",
            password="testpass123"
        )

        UserProfile.objects.create(
            user=user,
            email_verified=False,
            admin_approved=False
        )

        with self.assertRaises(IntegrityError):
            UserProfile.objects.create(
                user=user,
                email_verified=True,
                admin_approved=True
            )

class ViewsTest(TestCase):

    def test_home_view_status_code(self):
        response = self.client.get(reverse("accounts:home"))
        self.assertEqual(response.status_code, 302)
    
    def test_settings_view_requires_login(self):
        response = self.client.get(reverse("accounts:settings"))

        self.assertEqual(response.status_code, 302)
    def test_login_success(self):
        user = User.objects.create_user(
            username="loginuser",
            password="testpass123"
        )

        response = self.client.post(
            reverse("accounts:login"),
            {
                "username": "loginuser",
                "password": "testpass123"
            }
        )

        self.assertEqual(response.status_code, 302)


    def test_login_fail_redirects(self):
        User.objects.create_user(
            username="loginuser2",
            password="testpass123"
        )

        response = self.client.post(
            reverse("accounts:login"),
            {
                "username": "loginuser2",
                "password": "wrongpass"
            }
        )

        self.assertEqual(response.status_code, 302)

    def test_register_user(self):
        response = self.client.post(
            reverse("accounts:register"),
            {
                "username": "newuser",
                "password1": "StrongPass123!",
                "password2": "StrongPass123!"
            }
        )

        self.assertEqual(response.status_code, 302)


class GenerateUniqueUsernameTest(TestCase):
    """Tests pour la generation du nom d'utilisateur unique."""

    def test_premier_nom_disponible(self):
        """Si la base n'est pas prise, on retourne directement le nom de base"""
        nom = generate_unique_username("Jean", "Dupont")
        self.assertEqual(nom, "jean.dupont")

    def test_ajoute_un_suffixe_si_deja_pris(self):
        """Si jean.dupont existe, on doit retourner jean.dupont2"""
        User.objects.create_user(username="jean.dupont", password="x")

        nom = generate_unique_username("Jean", "Dupont")
        self.assertEqual(nom, "jean.dupont2")

    def test_incremente_le_suffixe(self):
        """Si jean.dupont et jean.dupont2 existent, on doit retourner jean.dupont3"""
        User.objects.create_user(username="jean.dupont", password="x")
        User.objects.create_user(username="jean.dupont2", password="x")

        nom = generate_unique_username("Jean", "Dupont")
        self.assertEqual(nom, "jean.dupont3")

    def test_exclude_user_id_permet_de_garder_son_nom(self):
        """Lors d'une mise a jour, on doit pouvoir conserver son propre nom d'utilisateur"""
        user = User.objects.create_user(username="alice.dupont", password="x")

        # On verifie qu'on peut "regenerer" le meme nom en s'excluant
        nom = generate_unique_username("Alice", "Dupont", exclude_user_id=user.pk)
        self.assertEqual(nom, "alice.dupont")

    def test_base_vide_donne_utilisateur(self):
        """Si prenom et nom sont vides, on doit avoir un nom par defaut"""
        nom = generate_unique_username("", "")
        self.assertEqual(nom, "utilisateur")


class SyncUserActivationStateTest(TestCase):
    """Tests pour la synchronisation du flag is_active avec le profil."""

    def test_superadmin_est_toujours_actif(self):
        """Un superuser doit rester actif meme sans profil valide"""
        admin = User.objects.create_superuser(
            username="admin",
            password="x",
            email="admin@x.fr",
        )
        admin.is_active = False
        admin.save()

        profile = UserProfile.objects.create(
            user=admin,
            email_verified=False,
            admin_approved=False,
        )

        sync_user_activation_state(admin, profile=profile)
        admin.refresh_from_db()

        self.assertTrue(admin.is_active)

    def test_utilisateur_valide_devient_actif(self):
        """Un user avec email_verified=True ET admin_approved=True doit etre actif"""
        user = User.objects.create_user(username="bob", password="x")
        user.is_active = False
        user.save()

        profile = UserProfile.objects.create(
            user=user,
            email_verified=True,
            admin_approved=True,
            admin_disabled=False,
        )

        sync_user_activation_state(user, profile=profile)
        user.refresh_from_db()

        self.assertTrue(user.is_active)

    def test_utilisateur_non_valide_devient_inactif(self):
        """Un user qui ne remplit pas les conditions doit etre desactive"""
        user = User.objects.create_user(username="charlie", password="x")
        user.is_active = True
        user.save()

        profile = UserProfile.objects.create(
            user=user,
            email_verified=False,
            admin_approved=False,
        )

        sync_user_activation_state(user, profile=profile)
        user.refresh_from_db()

        self.assertFalse(user.is_active)

    def test_admin_disabled_force_inactif(self):
        """Un user avec admin_disabled=True doit etre desactive meme s'il est verifie"""
        user = User.objects.create_user(username="david", password="x")

        profile = UserProfile.objects.create(
            user=user,
            email_verified=True,
            admin_approved=True,
            admin_disabled=True,
        )

        sync_user_activation_state(user, profile=profile)
        user.refresh_from_db()

        self.assertFalse(user.is_active)


class UserProfileAdditionalTest(TestCase):
    """Tests complementaires pour UserProfile."""

    def test_can_login_false_si_admin_disabled(self):
        """can_login doit retourner False si admin_disabled=True meme avec email_verified et admin_approved"""
        user = User.objects.create_user(username="eve", password="x")
        profile = UserProfile.objects.create(
            user=user,
            email_verified=True,
            admin_approved=True,
            admin_disabled=True,
        )

        self.assertFalse(profile.can_login())

    def test_is_superadmin_pour_un_superuser(self):
        """is_superadmin doit retourner True pour un superuser Django"""
        admin = User.objects.create_superuser(
            username="root_admin",
            password="x",
            email="r@x.fr",
        )
        profile = UserProfile.objects.create(user=admin)

        self.assertTrue(profile.is_superadmin)

    def test_is_superadmin_pour_un_user_normal(self):
        """is_superadmin doit retourner False pour un user classique"""
        user = User.objects.create_user(username="frank", password="x")
        profile = UserProfile.objects.create(user=user)

        self.assertFalse(profile.is_superadmin)

    def test_superadmin_peut_toujours_se_connecter(self):
        """can_login doit retourner True pour un superuser meme sans email_verified"""
        admin = User.objects.create_superuser(
            username="grace",
            password="x",
            email="g@x.fr",
        )
        profile = UserProfile.objects.create(
            user=admin,
            email_verified=False,
            admin_approved=False,
        )

        self.assertTrue(profile.can_login())