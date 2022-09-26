# Generated by Django 4.1 on 2022-09-06 01:17

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('apptoken', '0003_alter_applicationtoken_id_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='applicationtoken',
            name='id',
            field=models.CharField(default=uuid.uuid4, editable=False, max_length=80, primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='applicationtoken',
            name='token',
            field=models.UUIDField(auto_created=True, default=uuid.UUID('4caf52ea-7d4f-45c9-93a4-0e39cdb4bc52')),
        ),
    ]
