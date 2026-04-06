from django.http import HttpResponseForbidden

from .models import BannedIP
from .utils import get_client_ip


class IPBanMiddleware:
    EXCLUDED_PREFIXES = ["/static/", "/media/"]

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path

        for prefix in self.EXCLUDED_PREFIXES:
            if path.startswith(prefix):
                return self.get_response(request)

        ip_address = get_client_ip(request)

        if ip_address and BannedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden(
                "<h1>403 - Accès interdit</h1>"
                "<p>Contactez l'administrateur du site.</p>"
            )

        return self.get_response(request)