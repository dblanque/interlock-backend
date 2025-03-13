from .base import BaseModel
from .user import User
from django.db import models
from django.utils.crypto import get_random_string
from django.contrib.postgres.fields import ArrayField
import secrets

def generate_client_id():
    while True:
        client_id = get_random_string(24, "abcdefghijklmnopqrstuvwxyz0123456789")
        if not Application.objects.filter(client_id=client_id).exists():
            return client_id

def generate_client_secret():
    return secrets.token_urlsafe(48)  # Cryptographically secure

class Application(BaseModel):
    name = models.CharField(max_length=255)
    enabled = models.BooleanField(default=True)
    client_id = models.CharField(max_length=255, default=generate_client_id, unique=True)
    client_secret = models.CharField(max_length=255, default=generate_client_secret)
    redirect_uris = models.TextField(help_text="Comma-separated redirect URIs")
    scopes = models.TextField(default="openid profile email groups")

class ApplicationSecurityGroup(BaseModel):
    application = models.OneToOneField(Application, on_delete=models.CASCADE)
    enabled = models.BooleanField(default=True)
    users = models.ManyToManyField(User, blank=True)
    ldap_objects = ArrayField(models.CharField(max_length=255), blank=True, null=True)

    class Meta:
        db_table = "core_application_security_group"
