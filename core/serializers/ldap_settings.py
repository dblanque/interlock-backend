################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.serializers.ldap_settings
# Contains the serializer classes for LDAPPreset and LDAPSetting models

# ---------------------------------- IMPORTS -----------------------------------#
from rest_framework import serializers
from django.core.validators import RegexValidator
from core.models.ldap_settings import (
	LDAPSetting,
	LDAPPreset,
	LDAP_SETTING_NAME_CHOICES,
)
from core.models.types.settings import TYPE_AES_ENCRYPT
from core.constants.attrs.local import LOCAL_ATTR_TYPE
from rest_framework.exceptions import ValidationError
from core.models.types.settings import make_field_db_name
################################################################################


class LDAPPresetSerializer(serializers.ModelSerializer):
	name = serializers.CharField(
		validators=[RegexValidator("^[A-Za-z0-9_-]*$")]
	)

	class Meta:
		model = LDAPPreset
		fields = "__all__"


class LDAPSettingSerializer(serializers.ModelSerializer):
	name = serializers.ChoiceField(choices=LDAP_SETTING_NAME_CHOICES)
	preset = LDAPPresetSerializer(source="ldap_preset", read_only=True)

	class Meta:
		model = LDAPSetting
		fields = "__all__"

	def validate(self, attrs: dict):
		_type = attrs.get(LOCAL_ATTR_TYPE)
		if _type == TYPE_AES_ENCRYPT:
			errors = {}
			for fld in LDAPSetting.get_type_value_fields(_type):
				fld = make_field_db_name(fld)
				if not isinstance(self.initial_data[fld], bytes):
					errors[fld] = f"{fld} must be of type bytes"
				attrs[fld] = self.initial_data[fld]
			if errors:
				raise ValidationError(errors)
		return super().validate(attrs)
