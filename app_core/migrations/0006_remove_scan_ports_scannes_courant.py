from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("app_core", "0005_scan_ports_scannes_courant"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="scan",
            name="ports_scannes_courant",
        ),
    ]
