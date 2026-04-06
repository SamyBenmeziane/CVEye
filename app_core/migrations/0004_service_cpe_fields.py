from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("app_core", "0003_installationconfig"),
    ]

    operations = [
        migrations.AddField(
            model_name="service",
            name="cpe_match_string",
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name="service",
            name="cpe_name",
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
