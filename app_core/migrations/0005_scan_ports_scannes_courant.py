from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("app_core", "0004_service_cpe_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="scan",
            name="ports_scannes_courant",
            field=models.PositiveIntegerField(default=0),
        ),
    ]
