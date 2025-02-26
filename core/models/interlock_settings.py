################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.ilck_settings
# Description:	Contains default LDAP Setting definitions
#
#---------------------------------- IMPORTS -----------------------------------#
from .base import BaseModel
from django.db import models
from django.core.exceptions import ValidationError
from .types.settings import (
	TYPE_STRING,
	TYPE_BYTES,
	TYPE_BOOL,
	TYPE_INTEGER,
	TYPE_FLOAT
)
from django.utils.translation import gettext_lazy as _
################################################################################

class SETTING_TYPE_CHOICES(models.TextChoices):
	STRING = TYPE_STRING, "String"
	BYTES = TYPE_BYTES, "AES Encrypted"
	BOOL = TYPE_BOOL, "Boolean"
	INTEGER = TYPE_INTEGER, "Integer"
	FLOAT = TYPE_FLOAT, "Float"

SETTING_TYPE_MAP = {
	TYPE_STRING: "s_data_str",
	TYPE_BYTES: "s_data_bytes",
	TYPE_INTEGER: "s_data_int",
	TYPE_FLOAT: "s_data_float",
	TYPE_BOOL: "s_data_bool",
}

SETTING_KEY_AES = "AES_ENCRYPT_KEY"
SETTING_KEY_FERNET = "FERNET_KEY"
SETTING_KEYS: tuple[str] = (
	SETTING_KEY_AES,
	SETTING_KEY_FERNET,
)

class InterlockSetting(BaseModel):
	id = models.BigAutoField(verbose_name=_("id"), primary_key=True)
	s_name = models.CharField(
		verbose_name=_("name"),
		choices=[(k, f"ilck_{k.lower()}") for k in SETTING_KEYS],
		unique=True,
		null=False,
		blank=False,
		max_length=128
	)
	s_type = models.CharField(
		verbose_name=_("type"),
		choices=SETTING_TYPE_CHOICES.choices,
		null=False,
		blank=False
	)
	s_data_str = models.CharField(null=True, blank=True)
	s_data_bytes = models.BinaryField(null=True, blank=True)
	s_data_int = models.IntegerField(null=True, blank=True)
	s_data_float = models.FloatField(null=True, blank=True)
	s_data_bool = models.BooleanField(null=True, blank=True)

	def clean(self):
		for choice_type in SETTING_TYPE_CHOICES.choices:
			if self.s_type == choice_type:
				if getattr(self, SETTING_TYPE_MAP[choice_type]) is None:
					raise ValidationError(f"{SETTING_TYPE_MAP[choice_type]} cannot be null when type is {self.s_type}.")
		return super().clean()

	def save(self, *args, **kwargs):
		self.clean()
		super().save(*args, **kwargs)