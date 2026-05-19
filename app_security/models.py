from django.db import models

from app_core.models import Service


class Vulnerability(models.Model):
    service = models.ForeignKey(
        Service,
        on_delete=models.CASCADE,
        related_name="vulnerabilities",
    )
    cve_id = models.CharField(max_length=32)
    published = models.DateTimeField(blank=True, null=True)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=32, blank=True)
    score = models.FloatField(blank=True, null=True)
    correlation_type = models.CharField(max_length=32, default="none")
    query_value = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "vulnerability"
        ordering = ["-score", "cve_id"]
        unique_together = ("service", "cve_id")

    def __str__(self):
        """Retourne l'identifiant CVE suivi du service affecté."""
        return f"{self.cve_id} on {self.service}"
