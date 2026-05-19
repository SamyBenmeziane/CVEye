from django.utils.html import strip_tags


def clean_text_value(value, *, lower=False, max_length=None):
    """Nettoie une valeur textuelle : supprime les balises HTML, les espaces superflus,
    applique optionnellement la mise en minuscules et tronque à max_length caractères."""
    if value is None:
        return ""

    cleaned = strip_tags(str(value)).strip()

    if lower:
        cleaned = cleaned.lower()

    if max_length is not None:
        cleaned = cleaned[:max_length]

    return cleaned
