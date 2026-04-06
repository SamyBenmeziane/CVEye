import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("app_core", "0004_service_cpe_fields"),
    ]

    operations = [
        migrations.CreateModel(
            name="Vulnerability",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("cve_id", models.CharField(max_length=32)),
                ("published", models.DateTimeField(blank=True, null=True)),
                ("description", models.TextField(blank=True)),
                ("severity", models.CharField(blank=True, max_length=32)),
                ("score", models.FloatField(blank=True, null=True)),
                ("correlation_type", models.CharField(default="none", max_length=32)),
                ("query_value", models.CharField(blank=True, max_length=255)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "service",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="vulnerabilities",
                        to="app_core.service",
                    ),
                ),
            ],
            options={
                "db_table": "vulnerability",
                "ordering": ["-score", "cve_id"],
                "unique_together": {("service", "cve_id")},
            },
        ),
    ]
