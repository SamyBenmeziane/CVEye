from django.utils import timezone

from app_core.models import Cible
from app_scan.notification_service import envoyer_notification_resultat_scan
from app_scan.scheduler_utils import calculer_prochain_scan
from app_scan.scan_execution import execute_scan_for_target


def executer_scans_planifies():
    """Exécute tous les scans périodiques dont la date prochain_scan_le est atteinte ou dépassée.

    Pour chaque cible concernée : lance le scan, envoie la notification par e-mail, puis planifie
    la prochaine occurrence selon la périodicité configurée.
    """
    maintenant = timezone.now()

    cibles = Cible.objects.filter(
        owner__isnull=False,
        active=True,
        surveillance_active=True,
        prochain_scan_le__isnull=False,
        prochain_scan_le__lte=maintenant,
    )

    for cible in cibles:
        resultat = execute_scan_for_target(cible, cible.owner)
        scan_obj = resultat.get("scan_obj") if isinstance(resultat, dict) else None

        if scan_obj is not None:
            envoyer_notification_resultat_scan(scan_obj)

        cible.dernier_scan_le = maintenant
        cible.prochain_scan_le = calculer_prochain_scan(
            maintenant,
            cible.periodicite_scan,
        )
        cible.save(update_fields=["dernier_scan_le", "prochain_scan_le"])
