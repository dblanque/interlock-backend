
# signals.py
from core.models.application import Application
from django.db.models.signals import post_save
from django.dispatch import receiver
from oidc_provider.models import Client

@receiver(post_save, sender=Application)
def create_oidc_client(sender, instance, created, **kwargs):
    if created:
        Client.objects.create(
            name=instance.name,
            client_id=instance.client_id,
            client_secret=instance.client_secret,
            redirect_uris=instance.redirect_uris.split(','),
            scope=instance.scopes.split(),
            # Other OIDC client settings (e.g., token expiration)
        )