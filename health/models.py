import uuid

from django.db import models

# Create your models here.

class Health(models.Model):
    id = models.CharField(max_length=80, primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=200)
    token = models.UUIDField(auto_created=True, default=uuid.uuid4())
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
