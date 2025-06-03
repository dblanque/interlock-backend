from rest_framework import serializers
from django.core.validators import RegexValidator
from core.models.ldap_settings import (
	LDAPSetting,
	LDAPPreset,
	LDAP_SETTING_NAME_CHOICES,
)
from core.constants.attrs import (
	LOCAL_ATTR_DN,
	LOCAL_ATTR_VALUE,
	LOCAL_ATTR_TYPE,
	LOCAL_ATTR_NAME,
	LOCAL_ATTR_PRESET,
)
from core.models.types.settings import TYPE_AES_ENCRYPT
from core.constants.settings import (
	K_LDAP_FIELD_MAP,
)
from interlock_backend.encrypt import aes_encrypt
from core.ldap import defaults

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
		initial_data: dict = self.initial_data
		validated_data = super().validate(attrs)
		if not LOCAL_ATTR_VALUE in self.initial_data:
			raise serializers.ValidationError(
				f"{LOCAL_ATTR_VALUE} field is required."
			)
		param_value = initial_data.get(LOCAL_ATTR_VALUE)
		if validated_data.get(LOCAL_ATTR_TYPE) == TYPE_AES_ENCRYPT.lower():
			if not isinstance(param_value, str):
				raise serializers.ValidationError(
					f"{TYPE_AES_ENCRYPT} type setting value must be of type str"
				)
			validated_data[LOCAL_ATTR_VALUE] = aes_encrypt(param_value)
		elif validated_data.get(LOCAL_ATTR_NAME) == K_LDAP_FIELD_MAP:
			param_value: dict
			_non_nullables = list(
				defaults.LDAP_AUTH_USER_LOOKUP_FIELDS
			)
			_non_nullables.append(LOCAL_ATTR_DN)
			for _k, _v in param_value.items():
				_v: str
				if _v.lower() in (
					"none",
					"null",
				):
					if _k in set(_non_nullables):
						raise ValueError(
							f"{_k} is not a nullable field."
						)
					param_value[_k] = None
			attrs[LOCAL_ATTR_VALUE] = param_value
		else:
			attrs[LOCAL_ATTR_VALUE] = param_value
		return validated_data
