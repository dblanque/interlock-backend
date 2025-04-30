import re
from rest_framework import serializers
from core.models.application import User
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

def ldap_user_validator(value):
	def has_invalid_chars(s):
		return re.match(r'.*[\]\["\:\;\|\=\+\*\?\<\>\/\\\,]', s) != None

	return not has_invalid_chars(value)

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
	passwordConfirm = serializers.CharField(required=False)

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

	def validate_password_confirm(self, data: dict = None, raise_exc=True):
		if not data:
			if not hasattr(self, "data"):
				return False
			else:
				data = self.data
		_pwd: str = data.pop("password", None)
		_pwd_confirm: str = data.pop("passwordConfirm", None)
		if not _pwd:
			raise serializers.ValidationError(f"Missing password field.")
		if _pwd != _pwd_confirm:
			if raise_exc is True:
				raise serializers.ValidationError("Passwords do not match.")
			else:
				return False
		return True

class LDAPUserSerializer(serializers.Serializer):
	name = serializers.CharField(required=False)
	# Distinguished Name
	distinguishedName = serializers.CharField(required=False)
	type = serializers.CharField(required=False)
	# First Name
	givenName = serializers.CharField(required=False)
	# Last Name
	sn = serializers.CharField(required=False)
	# Username
	sAMAccountName = serializers.CharField(required=False)
	username = serializers.CharField(required=False)
	# Email
	mail = serializers.CharField(required=False)
	# Postal Code
	postalCode = serializers.CharField(required=False)
	# City
	l = serializers.CharField(required=False)
	# Country Name
	co = serializers.CharField(required=False)
	# Number Code for Country
	countryCode = serializers.IntegerField(required=False)
	# Two letter Country Code
	c = serializers.CharField(max_length=2, required=False)
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
	objectClass = serializers.ListField(required=False)
	objectCategory = serializers.CharField(required=False)
	objectSid = serializers.CharField(required=False)
	objectRid = serializers.IntegerField(required=False)
	sAMAccountType = serializers.CharField(required=False)
	memberOfObjects = serializers.ListField(required=False)
	is_enabled = serializers.BooleanField(required=False)
	permission_list = serializers.ListField(required=False)
