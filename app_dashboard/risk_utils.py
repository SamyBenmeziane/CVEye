SEVERITY_HIGH_LABEL = "\u00c9lev\u00e9e"
RISK_HIGH_LABEL = "\u00c9lev\u00e9"


def normalize_severity_label(severity):
    """Normalise une étiquette de sévérité provenant de sources variées vers un libellé stable en français.

    Les valeurs possibles en retour sont : 'Critique', 'Élevée', 'Moyenne', 'Faible', 'Inconnue'.
    """
    value = (severity or "").strip().upper()
    if value in {"CRITICAL", "CRITIQUE"}:
        return "Critique"
    if value in {"HIGH", "HAUTE", "ELEVATED", "ELEVEE", "\u00c9LEV\u00c9E"}:
        return SEVERITY_HIGH_LABEL
    if value in {"MEDIUM", "MOYENNE", "MOYEN"}:
        return "Moyenne"
    if value in {"LOW", "FAIBLE"}:
        return "Faible"
    return "Inconnue"


def compute_vulnerability_count_risk_label(vulnerability_count):
    """Retourne un niveau de risque global selon le nombre total de vulnérabilités détectées.

    Seuils : Critique (≥5), Élevé (≥3), Moyen (≥1), Faible (0).
    """
    if vulnerability_count >= 5:
        return "Critique"
    if vulnerability_count >= 3:
        return RISK_HIGH_LABEL
    if vulnerability_count >= 1:
        return "Moyen"
    return "Faible"


def compute_severity_counts_risk_label(severity_counts):
    """Retourne le niveau de risque le plus élevé observé dans un dictionnaire de compteurs de sévérités."""
    if severity_counts["Critique"] > 0:
        return "Critique"
    if severity_counts[SEVERITY_HIGH_LABEL] > 0:
        return RISK_HIGH_LABEL
    if severity_counts["Moyenne"] > 0:
        return "Moyen"
    return "Faible"
