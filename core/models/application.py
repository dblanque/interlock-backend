from core.models.base import BaseModel
from core.models.user import User
from django.db import models
from django.utils.crypto import get_random_string
from django.contrib.postgres.fields import ArrayField
import secrets
from uuid import uuid5
from interlock_backend.settings import INTERLOCK_NAMESPACE, SECRET_KEY


def generate_client_id() -> str:
	"""Generates a 24 character client id, retries up to 10 times and gives up.
	The odds of generating an existing id 10 times in a row are very low.
	"""
	tries = 0
	while True and tries <= 10:
		client_id = get_random_string(
			24, "abcdefghijklmnopqrstuvwxyz0123456789"
		)
		if not Application.objects.filter(client_id=client_id).exists():
			return client_id
		tries += 1


def generate_client_secret() -> str:
	"""Generates a 48 character urlsafe token."""
	_urlsafe_token = secrets.token_urlsafe(48)
	return _urlsafe_token  # Cryptographically secure


class Application(BaseModel):
	name = models.CharField(max_length=255)
	enabled = models.BooleanField(default=True)
	client_id = models.CharField(
		max_length=25, default=generate_client_id, unique=True
	)
	client_secret = models.CharField(
		max_length=129, default=generate_client_secret
	)
	redirect_uris = models.TextField(help_text="Comma-separated redirect URIs")
	scopes = models.TextField(default="openid profile email groups")


class ApplicationSecurityGroup(BaseModel):
	application = models.OneToOneField(Application, on_delete=models.CASCADE)
	enabled = models.BooleanField(default=True)
	users = models.ManyToManyField(User, blank=True, related_name="asg_member")
	ldap_objects = ArrayField(
		models.CharField(max_length=255), blank=True, null=True
	)
	uuid = models.UUIDField(default=None, editable=False)

	def generate_uuid(self):
		return uuid5(
			INTERLOCK_NAMESPACE,
			"asg_%s_%s_%s"
			% (
				str(self.id),
				str(self.application.id),
				SECRET_KEY,
			),
		)

	def save(self, *args, **kwargs):
		if not self.uuid:
			self.uuid = self.generate_uuid()
		super().save(*args, **kwargs)

	class Meta:
		db_table = "core_application_security_group"
