import threading
import time

from django.conf import settings


SCAN_PROGRESS_TIMEOUT = int(getattr(settings, "CACHE_TIMEOUT", 1800))
_SCAN_PROGRESS = {}
_SCAN_PROGRESS_LOCK = threading.Lock()


def _scan_progress_key(scan_id):
    """Convertit l'identifiant du scan en clé string utilisée dans le dictionnaire partagé."""
    return str(scan_id)


def _prune_expired_progress(now=None):
    """Supprime les entrées de progression dont le TTL a expiré du dictionnaire partagé."""
    current_time = time.time() if now is None else now
    expired_keys = []

    for scan_key, payload in _SCAN_PROGRESS.items():
        expires_at = payload.get("_expires_at")
        if expires_at is not None and expires_at <= current_time:
            expired_keys.append(scan_key)

    for scan_key in expired_keys:
        _SCAN_PROGRESS.pop(scan_key, None)


def set_scan_progress(scan_id, **payload):
    """Enregistre ou met à jour la progression d'un scan en fusionnant les nouvelles valeurs avec l'existant.

    Chaque appel réinitialise le TTL de l'entrée. Retourne le payload complet sans la clé interne _expires_at.
    """
    scan_key = _scan_progress_key(scan_id)
    now = time.time()

    with _SCAN_PROGRESS_LOCK:
        _prune_expired_progress(now)
        # On fusionne avec lexistant pour ne pas perdre les infos deja posees
        current_payload = dict(_SCAN_PROGRESS.get(scan_key, {}))
        current_payload.update(payload)
        current_payload["_expires_at"] = now + SCAN_PROGRESS_TIMEOUT
        _SCAN_PROGRESS[scan_key] = current_payload

        response_payload = current_payload.copy()

    response_payload.pop("_expires_at", None)
    return response_payload


def get_scan_progress(scan_id):
    """Retourne le payload de progression courant d'un scan, ou None si absent ou expiré."""
    scan_key = _scan_progress_key(scan_id)
    now = time.time()

    with _SCAN_PROGRESS_LOCK:
        _prune_expired_progress(now)
        payload = _SCAN_PROGRESS.get(scan_key)
        if not payload:
            return None
        response_payload = payload.copy()

    response_payload.pop("_expires_at", None)
    return response_payload


def pop_scan_progress(scan_id):
    """Retourne et supprime atomiquement l'entrée de progression d'un scan du dictionnaire partagé."""
    scan_key = _scan_progress_key(scan_id)
    now = time.time()

    with _SCAN_PROGRESS_LOCK:
        _prune_expired_progress(now)
        payload = _SCAN_PROGRESS.pop(scan_key, None)
        if not payload:
            return None
        response_payload = payload.copy()

    response_payload.pop("_expires_at", None)
    return response_payload
