from .base import BaseModel
from django.db import models

class Application(BaseModel):
    name = models.CharField(max_length=255)
    client_id = models.CharField(max_length=255, unique=True)
    client_secret = models.CharField(max_length=255)
    redirect_uris = models.TextField(help_text="Comma-separated redirect URIs")
    scopes = models.TextField(default="openid profile email groups")
