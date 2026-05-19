from django.core.management.base import BaseCommand

from app_scan.taches import executer_scans_planifies


class Command(BaseCommand):
    """Commande de gestion Django pour lancer manuellement les scans planifies."""

    help = "Lance les scans planifiés des cibles"

    def handle(self, *args, **options):
        """Déclenche immédiatement l'exécution des scans périodiques échus et affiche un message de succès."""
        executer_scans_planifies()
        self.stdout.write(
            self.style.SUCCESS("Scans planifiés exécutés avec succès.")
        )
