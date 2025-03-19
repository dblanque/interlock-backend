################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.ilck_settings
# Description:	Contains default LDAP Setting definitions
#
# ---------------------------------- IMPORTS -----------------------------------#
from core.models.setting.base import BaseSetting, add_fields_from_dict
from django.db import models
from core.models.types.settings import (
	INTERLOCK_SETTING_FIELDS,
	TYPE_BYTES,
	TYPE_BOOL,
)
from django.utils.translation import gettext_lazy as _
################################################################################

INTERLOCK_SETTING_TABLE = "core_interlock_setting"
INTERLOCK_SETTING_AES_KEY = "ILCK_AES_KEY"
INTERLOCK_SETTING_ENABLE_LDAP = "ILCK_ENABLE_LDAP"
INTERLOCK_SETTING_MAP = {
	INTERLOCK_SETTING_AES_KEY: TYPE_BYTES,
	INTERLOCK_SETTING_ENABLE_LDAP: TYPE_BOOL,
}
INTERLOCK_SETTING_PUBLIC = (INTERLOCK_SETTING_ENABLE_LDAP,)
INTERLOCK_SETTING_NAME_CHOICES = tuple([(k, k.upper()) for k in INTERLOCK_SETTING_MAP.keys()])
INTERLOCK_SETTING_TYPE_CHOICES = tuple([(k, k.upper()) for k in INTERLOCK_SETTING_FIELDS.keys()])


@add_fields_from_dict(INTERLOCK_SETTING_FIELDS)
class InterlockSetting(BaseSetting):
	setting_fields = INTERLOCK_SETTING_FIELDS
	id = models.BigAutoField(verbose_name=_("id"), primary_key=True)
	name = models.CharField(
		verbose_name=_("type"), choices=INTERLOCK_SETTING_NAME_CHOICES, null=False, blank=False
	)
	type = models.CharField(
		verbose_name=_("type"), choices=INTERLOCK_SETTING_TYPE_CHOICES, null=False, blank=False
	)

	def save(self, *args, **kwargs):
		self.clean()
		super().save(*args, **kwargs)

	class Meta:
		db_table = INTERLOCK_SETTING_TABLE
