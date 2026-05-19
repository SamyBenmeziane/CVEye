from datetime import timedelta


def calculer_prochain_scan(date_base, periodicite):
    """Calcule la prochaine date de scan en ajoutant l'intervalle correspondant à la périodicité.

    Valeurs acceptées pour periodicite : 'toutes_les_heures', 'tous_les_jours',
    'toutes_les_semaines', 'tous_les_mois' (30 jours). Retourne None pour toute autre valeur.
    """
    if periodicite == "toutes_les_heures":
        return date_base + timedelta(hours=1)

    if periodicite == "tous_les_jours":
        return date_base + timedelta(days=1)

    if periodicite == "toutes_les_semaines":
        return date_base + timedelta(weeks=1)

    if periodicite == "tous_les_mois":
        return date_base + timedelta(days=30)

    return None
