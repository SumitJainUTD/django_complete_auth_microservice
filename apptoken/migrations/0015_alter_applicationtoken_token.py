# Generated by Django 4.1 on 2022-09-14 05:44

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('apptoken', '0014_alter_applicationtoken_token'),
    ]

    operations = [
        migrations.AlterField(
            model_name='applicationtoken',
            name='token',
            field=models.UUIDField(auto_created=True, default=uuid.UUID('37e6554c-b776-4ee1-91cf-1eec0396d2f2')),
        ),
    ]