from rest_framework.exceptions import ValidationError
from rest_framework import serializers
from core.models.application import User
from django.core.validators import validate_email
from core.ldap.constants import (
	LDAP_DATE_FORMAT,
	LOCAL_ATTR_USERNAME,
	LOCAL_ATTR_PASSWORD,
	LDAP_ATTR_EMAIL,
	LDAP_ATTR_FIRST_NAME,
	LDAP_ATTR_LAST_LOGIN,
	LDAP_ATTR_INITIALS,
	LDAP_ATTR_PHONE,
	LDAP_ATTR_WEBSITE,
	LDAP_ATTR_ADDRESS,
	LDAP_ATTR_POSTAL_CODE,
	LDAP_ATTR_CITY,
	LDAP_ATTR_STATE,
	LDAP_ATTR_COUNTRY,
)
from core.serializers.ldap import (
	ldap_user_validator,
	DistinguishedNameField,
	ldap_user_validator_se,
	country_validator,
	country_iso_validator,
	country_dcc_validator,
	ldap_permission_validator,
)

FIELD_VALIDATORS = {
	LOCAL_ATTR_USERNAME: ldap_user_validator,  # username
	LOCAL_ATTR_PASSWORD: None,  # password
	LDAP_ATTR_EMAIL: None,  # email
	LDAP_ATTR_FIRST_NAME: None,  # first_name
	LDAP_ATTR_LAST_LOGIN: None,  # last_name
	LDAP_ATTR_INITIALS: None,  # initials
	LDAP_ATTR_PHONE: None,  # phone_number
	LDAP_ATTR_WEBSITE: None,  # webpage
	LDAP_ATTR_ADDRESS: None,  # street_address
	LDAP_ATTR_POSTAL_CODE: None,  # postal_code
	LDAP_ATTR_CITY: None,  # town
	LDAP_ATTR_STATE: None,  # state_province
	LDAP_ATTR_COUNTRY: None,  # country
}
class UserSerializer(serializers.ModelSerializer):
	passwordConfirm = serializers.CharField(
		required=False,
		write_only=True,
		allow_blank=True,
	)

	class Meta:
		model = User
		fields = (
			"username",
			"first_name",
			"last_name",
			"email",
			"password",
			"passwordConfirm",
		)
		extra_kwargs = {
			'password': {'write_only': True}  # Also hide password in responses
		}

	def validate(self, data: dict):
		"""Handle password confirmation validation"""
		password = data.get('password', None)
		password_confirm = data.get('passwordConfirm', None)

		# Only validate if password is being set/changed
		if password is not None:
			if password_confirm is None:
				raise serializers.ValidationError(
					{"passwordConfirm": "Password confirmation is required when setting password"}
				)
			if password != password_confirm:
				raise serializers.ValidationError(
					{"passwordConfirm": "Passwords do not match"}
				)

		# Remove passwordConfirm from data as it's not a model field
		data.pop('passwordConfirm', None)
		return data

class LDAPUserSerializer(serializers.Serializer):
	name = serializers.CharField(required=False)
	password = serializers.CharField(required=False)
	path = DistinguishedNameField()

	# Distinguished Name
	distinguishedName = DistinguishedNameField()
	type = serializers.CharField(required=False)
	# First Name
	givenName = serializers.CharField(
		allow_blank=True,
		required=False,
	)
	# Last Name
	sn = serializers.CharField(
		allow_blank=True,
		required=False,
	)
	# Username
	sAMAccountName = serializers.CharField(required=False, min_length=1, max_length=21, validators=[ldap_user_validator_se])
	username = serializers.CharField(required=False, min_length=1, max_length=21, validators=[ldap_user_validator_se])
	# Email
	mail = serializers.CharField(
		allow_blank=True,
		required=False,
		validators=[validate_email]
	)
	email = serializers.CharField(
		allow_blank=True,
		required=False,
		validators=[validate_email],
	)
	# Postal Code
	postalCode = serializers.CharField(required=False)
	# City
	l = serializers.CharField(required=False)
	# Country Name
	co = serializers.CharField(
		required=False,
		validators=[country_validator]
	)
	# Number Code for Country
	countryCode = serializers.IntegerField(required=False, validators=[country_dcc_validator])
	# Two letter Country Code
	c = serializers.CharField(max_length=3, required=False, validators=[country_iso_validator])
	userPrincipalName = serializers.CharField(required=False)
	userAccountControl = serializers.IntegerField(required=False)
	whenCreated = serializers.DateTimeField(
		format=LDAP_DATE_FORMAT,
		input_formats=[LDAP_DATE_FORMAT, "iso-8601"],
		required=False,
	)
	whenChanged = serializers.DateTimeField(
		format=LDAP_DATE_FORMAT,
		input_formats=[LDAP_DATE_FORMAT, "iso-8601"],
		required=False,
	)
	lastLogonTimestamp = serializers.DateTimeField(
		format=LDAP_DATE_FORMAT,
		input_formats=[LDAP_DATE_FORMAT, "iso-8601"],
		required=False,
	)
	accountExpires = serializers.DateTimeField(
		format=LDAP_DATE_FORMAT,
		input_formats=[LDAP_DATE_FORMAT, "iso-8601"],
		required=False,
	)
	lastLogon = serializers.IntegerField(required=False)
	badPwdCount = serializers.IntegerField(required=False)
	pwdLastSet = serializers.IntegerField(required=False)
	primaryGroupID = serializers.IntegerField(required=False)
	objectClass = serializers.ListField(required=False, child=serializers.CharField())
	objectCategory = serializers.CharField(required=False)
	objectSid = serializers.CharField(required=False)
	objectRid = serializers.IntegerField(required=False)
	sAMAccountType = serializers.CharField(required=False)
	memberOfObjects = serializers.ListField(required=False, child=serializers.DictField())
	is_enabled = serializers.BooleanField(required=False)
	permission_list = serializers.ListField(
		required=False,
		child=serializers.CharField(validators=[ldap_permission_validator])
	)
	groupsToAdd = serializers.ListField(required=False, child=DistinguishedNameField())
	groupsToRemove = serializers.ListField(required=False, child=DistinguishedNameField())
