# Generated by Django 4.1 on 2022-09-15 03:24

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('apptoken', '0015_alter_applicationtoken_token'),
    ]

    operations = [
        migrations.AlterField(
            model_name='applicationtoken',
            name='token',
            field=models.UUIDField(auto_created=True, default=uuid.UUID('db1c6528-f8b7-4c1b-b377-1f5606beb994')),
        ),
    ]
