################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.user
# Contains the Model for Interlock's LDAP Synced and Local Users
#
# --------------------------------- IMPORTS ---------------------------------- #
from django.contrib.auth.base_user import (
	BaseUserManager as DjangoBaseUserManager,
)
from django.contrib.auth.hashers import (
	make_password,
	check_password,
	is_password_usable,
)
from django.contrib.postgres.fields import ArrayField
from django.contrib.auth.models import PermissionsMixin
from django.db import models
from django.utils.crypto import salted_hmac
from django.utils.translation import gettext_lazy as _

from core.models.base import BaseModel
from interlock_backend.settings import (
	DEFAULT_SUPERUSER_USERNAME,
	DEFAULT_SUPERUSER_PASSWORD,
)
from django.core.validators import validate_email
from core.serializers.ldap import ldap_user_validator_se
from typing import TYPE_CHECKING
from django.db.models.query import QuerySet
from typing import ClassVar
from typing_extensions import Self
# ---------------------------------------------------------------------------- #

if TYPE_CHECKING:
	from core.models.application import ApplicationSecurityGroup


class BaseUserManager(DjangoBaseUserManager):
	use_in_migrations = True

	def get_queryset(self):
		return super().get_queryset().exclude(deleted=True)

	def get_full_queryset(self):
		return super().get_queryset()

	def _create_user(self, username, password, **extra_fields):
		"""
		Create and save a user with the given username and password.
		"""
		if not username:
			raise ValueError("Users must have a username")
		username = username.lower()
		user = self.model(username=username, **extra_fields)
		user.set_password(password)
		user.save(using=self._db)
		return user

	def create_user(self, username=None, password=None, **extra_fields):
		return self._create_user(username, password, **extra_fields)

	def create_superuser(self, username=None, password=None, **extra_fields):
		extra_fields.setdefault("is_staff", True)
		extra_fields.setdefault("is_superuser", True)

		if extra_fields.get("is_staff") is not True:
			raise ValueError("Superuser must have is_staff=True.")
		if extra_fields.get("is_superuser") is not True:
			raise ValueError("Superuser must have is_superuser=True.")

		return self._create_user(username, password, **extra_fields)

	def create_default_superuser(self, **extra_fields):
		extra_fields.setdefault("is_staff", True)
		extra_fields.setdefault("is_superuser", True)

		if extra_fields.get("is_staff") is not True:
			raise ValueError("Superuser must have is_staff=True.")
		if extra_fields.get("is_superuser") is not True:
			raise ValueError("Superuser must have is_superuser=True.")

		return self.create_user(
			DEFAULT_SUPERUSER_USERNAME,
			DEFAULT_SUPERUSER_PASSWORD,
			**extra_fields,
		)


class BaseUser(BaseModel, PermissionsMixin):
	USERNAME_FIELD = "username"
	REQUIRED_FIELDS = []
	objects = BaseUserManager()

	id = models.BigAutoField(primary_key=True)
	username = models.CharField(
		_("username"),
		max_length=128,
		unique=True,
		null=False,
		blank=False,
		db_index=True,
		validators=[ldap_user_validator_se],
	)
	password = models.CharField(_("password"), max_length=128)
	last_login = models.DateTimeField(_("last login"), blank=True, null=True)
	email = models.EmailField(
		_("email address"),
		unique=True,
		db_index=True,
		null=True,
		validators=[validate_email],
		blank=True,
	)
	is_staff = models.BooleanField(
		_("staff status"),
		default=False,
		help_text=_("Designates whether the user is staff."),
	)
	is_superuser = models.BooleanField(
		_("admin status"),
		default=False,
		help_text=_(
			"Designates whether the user can log into this admin site and has superadmin privileges."
		),
	)

	def __str__(self):
		return self.username

	def get_username(self):
		return self.username

	def get_email(self):
		return self.email

	def get_uid(self):
		return self.id

	@property
	def date_joined(self):
		return self.created_at

	@property
	def is_anonymous(self):
		"""
		Always return False. This is a way of comparing User objects to
		anonymous users.
		"""
		return False

	@property
	def is_authenticated(self):
		"""
		Always return True. This is a way to tell if the user has been
		authenticated in templates.
		"""
		return True

	@property
	def is_active(self):
		return not self.deleted

	# This has to be reworked for LDAP Compatibility
	def set_password(self, raw_password):
		self.password = make_password(raw_password)
		self._password = raw_password

	# This has to be reworked for LDAP Compatibility
	def check_password(self, raw_password):
		"""
		Return a boolean of whether the raw_password was correct. Handles
		hashing formats behind the scenes.
		"""

		def setter(raw_password):
			self.set_password(raw_password)
			# Password hash upgrades shouldn't be considered password changes.
			self._password = None
			self.save(update_fields=["password"])

		return check_password(raw_password, self.password, setter)

	def set_unusable_password(self):
		# Set a value that will never be a valid hash
		self.password = make_password(None)

	def has_usable_password(self):
		"""
		Return False if set_unusable_password() has been called for this user.
		"""
		return is_password_usable(self.password)

	def get_session_auth_hash(self):
		"""
		Return an HMAC of the password field.
		"""
		key_salt = (
			"django.contrib.auth.models.AbstractBaseUser.get_session_auth_hash"
		)
		return salted_hmac(key_salt, self.password).hexdigest()

	def get_session_auth_fallback_hash(self):
		for fallback_secret in []:
			yield self._get_session_auth_hash(secret=fallback_secret)

	@classmethod
	def get_email_field_name(cls):
		try:
			return cls.EMAIL_FIELD
		except AttributeError:
			return "email"

	class Meta:
		abstract = True


USER_LDAP_FIELD_PREFIX = "ldap"
USER_PASSWORD_FIELDS = (
	f"{USER_LDAP_FIELD_PREFIX}_password_aes",
	f"{USER_LDAP_FIELD_PREFIX}_password_ct",
	f"{USER_LDAP_FIELD_PREFIX}_password_nonce",
	f"{USER_LDAP_FIELD_PREFIX}_password_tag",
)
USER_TYPE_LOCAL = "local"
USER_TYPE_LDAP = "ldap"
USER_TYPE_CHOICES = (
	(USER_TYPE_LOCAL, f"{USER_TYPE_LOCAL.capitalize()} User"),
	(USER_TYPE_LDAP, f"{USER_TYPE_LDAP.upper()} User"),
)


class User(BaseUser):
	objects: ClassVar[BaseUserManager[Self]]

	class Meta:
		verbose_name = _("User")
		verbose_name_plural = _("Users")
		constraints = [
			models.CheckConstraint(
				condition=models.Q(
					ldap_password_aes=None,
					ldap_password_ct=None,
					ldap_password_nonce=None,
					ldap_password_tag=None,
				)
				| models.Q(
					ldap_password_aes__isnull=False,
					ldap_password_ct__isnull=False,
					ldap_password_nonce__isnull=False,
					ldap_password_tag__isnull=False,
				),
				name="user_password_crypt_data_all_or_none",
			)
		]

	first_name = models.CharField(
		_("First name"), max_length=255, null=True, blank=True
	)
	last_name = models.CharField(
		_("Last name"), max_length=255, null=True, blank=True
	)
	_distinguished_name = models.CharField(
		_("Distinguished Name"), max_length=128, null=True, blank=True
	)
	user_type = models.CharField(
		_("User Type"),
		choices=USER_TYPE_CHOICES,
		null=False,
		blank=False,
		default=USER_TYPE_LOCAL,
	)
	recovery_codes = ArrayField(
		models.CharField(max_length=32),
		verbose_name="Recovery Codes",
		null=True,
		blank=True,
	)
	is_enabled = models.BooleanField(null=False, default=True)

	# Encrypted AES Key
	ldap_password_aes = models.BinaryField(null=True, blank=True, default=None)
	# Cipher Text
	ldap_password_ct = models.BinaryField(null=True, blank=True, default=None)
	ldap_password_nonce = models.BinaryField(
		null=True, blank=True, default=None
	)
	ldap_password_tag = models.BinaryField(null=True, blank=True, default=None)

	# Avoids circular imports
	if TYPE_CHECKING:
		asg_member: QuerySet[ApplicationSecurityGroup]

	@property
	def encrypted_password(self):
		"""Returns tuple of BinaryField memoryview objects"""
		return tuple([getattr(self, f) for f in USER_PASSWORD_FIELDS])

	@property
	def encrypted_password_bytes(self):
		"""Returns tuple of bytes converted from BinaryField memoryview objects"""
		return tuple([getattr(self, f).tobytes for f in USER_PASSWORD_FIELDS])

	@property
	def distinguished_name(self):
		if self.user_type != USER_TYPE_LDAP:
			return None
		return self._distinguished_name

	@distinguished_name.setter
	def distinguished_name(self, v):
		if self.user_type != USER_TYPE_LDAP:
			self._distinguished_name = None
		else:
			self._distinguished_name = v

	def __setattr__(self, name, value):
		if name == "distinguished_name":
			if self.user_type != USER_TYPE_LDAP:
				super().__setattr__("_distinguished_name", None)
			else:
				super().__setattr__("_distinguished_name", value)
		else:
			super().__setattr__(name, value)

	def is_user_local(self):
		return self.user_type == USER_TYPE_LOCAL

	def save(self, *args, **kwargs):
		"""Ensure consistency on save"""
		if self.user_type != USER_TYPE_LDAP:
			self.distinguished_name = None
		super().save(*args, **kwargs)
