# Generated by Django 4.1 on 2022-09-14 05:39

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('apptoken', '0013_alter_applicationtoken_token'),
    ]

    operations = [
        migrations.AlterField(
            model_name='applicationtoken',
            name='token',
            field=models.UUIDField(auto_created=True, default=uuid.UUID('47c13c9d-c98b-48e9-ade3-548ee5bb73a3')),
        ),
    ]
