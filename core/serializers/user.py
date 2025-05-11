from rest_framework.exceptions import ValidationError
from rest_framework import serializers
from core.models.application import User
from django.core.validators import validate_email
from core.constants.attrs import (
	LDAP_DATE_FORMAT,
	LOCAL_ATTR_USERNAME,
	LOCAL_ATTR_FIRST_NAME,
	LOCAL_ATTR_LAST_NAME,
	LOCAL_ATTR_EMAIL,
	LOCAL_ATTR_PASSWORD,
	LOCAL_ATTR_PASSWORD_CONFIRM,
)
from core.serializers.ldap import (
	DistinguishedNameField,
	ldap_user_validator_se,
	country_validator,
	country_iso_validator,
	country_dcc_validator,
	ldap_permission_validator,
	website_validator,
)


def validate_password_match(password: str, password_confirm: str) -> str:
	"""Validates password match with confirm field, returns value if valid"""
	# Only validate if password is being set/changed
	if password:
		if not password_confirm:
			raise serializers.ValidationError(
				{
					LOCAL_ATTR_PASSWORD_CONFIRM: "Password confirmation is required when setting password"
				}
			)
		if password != password_confirm:
			raise serializers.ValidationError(
				{LOCAL_ATTR_PASSWORD_CONFIRM: "Passwords do not match"}
			)
	return password


class UserSerializer(serializers.ModelSerializer):
	password_confirm = serializers.CharField(
		required=False,
		write_only=True,
		allow_blank=True,
	)

	class Meta:
		model = User
		fields = (
			LOCAL_ATTR_USERNAME,
			LOCAL_ATTR_FIRST_NAME,
			LOCAL_ATTR_LAST_NAME,
			LOCAL_ATTR_EMAIL,
			LOCAL_ATTR_PASSWORD,
			LOCAL_ATTR_PASSWORD_CONFIRM,
		)
		extra_kwargs = {
			LOCAL_ATTR_PASSWORD: {
				"write_only": True
			}  # Also hide password in responses
		}

	def validate(self, data: dict):
		"""Handle password confirmation validation"""
		password = data.get(LOCAL_ATTR_PASSWORD, None)
		password_confirm = data.get(LOCAL_ATTR_PASSWORD_CONFIRM, None)
		validate_password_match(password, password_confirm)

		# Remove password_confirm from data as it's not a model field
		data.pop(LOCAL_ATTR_PASSWORD_CONFIRM, None)
		return data


class LDAPUserSerializer(serializers.Serializer):
	name = serializers.CharField(required=False)
	# Distinguished Name
	distinguished_name = DistinguishedNameField(required=False)
	# Username
	username = serializers.CharField(
		required=False,
		min_length=1,
		max_length=21,
		validators=[ldap_user_validator_se],
	)
	# Email
	email = serializers.CharField(
		allow_blank=True,
		allow_null=True,
		required=False,
		validators=[validate_email],
	)
	password = serializers.CharField(
		allow_blank=True, required=False, write_only=True
	)
	password_confirm = serializers.CharField(
		required=False,
		write_only=True,
		allow_blank=True,
	)
	path = DistinguishedNameField(required=False, write_only=True)

	# First Name
	first_name = serializers.CharField(
		allow_blank=True,
		allow_null=True,
		required=False,
	)
	# Last Name
	last_name = serializers.CharField(
		allow_blank=True,
		allow_null=True,
		required=False,
	)
	# Website
	website = serializers.CharField(
		allow_blank=True,
		allow_null=True,
		required=False,
		validators=[website_validator],
	)
	# Phone Number
	phone = serializers.CharField(
		allow_blank=True,
		allow_null=True,
		required=False,
		max_length=33,
		min_length=2,
	)
	# Street Address
	street_address = serializers.CharField(
		allow_blank=True,
		allow_null=True,
		required=False,
		max_length=254,
		min_length=2,
	)
	# Postal Code
	postal_code = serializers.CharField(
		allow_blank=True,
		allow_null=True,
		required=False,
	)
	# City
	city = serializers.CharField(
		allow_blank=True,
		allow_null=True,
		required=False,
	)
	# State / Province
	state_province = serializers.CharField(
		allow_blank=True,
		allow_null=True,
		required=False,
	)
	# Country Name
	country_name = serializers.CharField(
		allow_blank=True,
		allow_null=True,
		required=False,
		validators=[country_validator],
	)
	# Number Code for Country
	country_code_dcc = serializers.IntegerField(
		allow_null=True, required=False, validators=[country_dcc_validator]
	)
	# Two letter Country Code
	country_code_iso = serializers.CharField(
		allow_blank=True,
		allow_null=True,
		max_length=3,
		required=False,
		validators=[country_iso_validator],
	)
	user_principal_name = serializers.CharField(required=False)
	user_account_control = serializers.IntegerField(required=False)
	created_at = serializers.DateTimeField(
		format=LDAP_DATE_FORMAT,
		input_formats=[LDAP_DATE_FORMAT, "iso-8601"],
		required=False,
	)
	modified_at = serializers.DateTimeField(
		format=LDAP_DATE_FORMAT,
		input_formats=[LDAP_DATE_FORMAT, "iso-8601"],
		required=False,
	)
	login_timestamp = serializers.DateTimeField(
		format=LDAP_DATE_FORMAT,
		input_formats=[LDAP_DATE_FORMAT, "iso-8601"],
		required=False,
	)
	expires_at = serializers.DateTimeField(
		format=LDAP_DATE_FORMAT,
		input_formats=[LDAP_DATE_FORMAT, "iso-8601"],
		required=False,
	)
	last_login_win32 = serializers.IntegerField(required=False)
	bad_password_count = serializers.IntegerField(required=False)
	password_set_at = serializers.IntegerField(required=False)
	primary_group_id = serializers.IntegerField(required=False)
	object_class = serializers.ListField(
		required=False, child=serializers.CharField()
	)
	object_category = serializers.CharField(required=False)
	object_security_id = serializers.CharField(required=False)
	object_relative_id = serializers.IntegerField(required=False)
	account_type = serializers.CharField(required=False)
	is_enabled = serializers.BooleanField(required=False)
	permissions = serializers.ListField(
		required=False,
		child=serializers.CharField(validators=[ldap_permission_validator]),
	)
	# TODO - Serialize groups with LDAPGroupSerializer
	groups = serializers.ListField(
		required=False, child=serializers.DictField()
	)
	groups_to_add = serializers.ListField(
		required=False, child=DistinguishedNameField()
	)
	groups_to_remove = serializers.ListField(
		required=False, child=DistinguishedNameField()
	)

	def validate(self, data: dict):
		"""Handle extra validation"""
		password = data.get(LOCAL_ATTR_PASSWORD, None)
		password_confirm = data.get(LOCAL_ATTR_PASSWORD_CONFIRM, None)
		validate_password_match(password, password_confirm)

		# Remove password_confirm from data as it's not a model field
		data.pop(LOCAL_ATTR_PASSWORD_CONFIRM, None)
		return data
