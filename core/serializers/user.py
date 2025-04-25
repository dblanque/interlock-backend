import re
from rest_framework import serializers
from core.models.application import User
from core.ldap.constants import LDAP_DATE_FORMAT

FIELD_VALIDATORS = {
	"username": "ldap_user",  # username
	"password": None,  # password
	"mail": None,  # email
	"givenName": None,  # first_name
	"sn": None,  # last_name
	"initials": None,  # initials
	"telephoneNumber": None,  # phone_number
	"wWWHomePage": None,  # webpage
	"streetAddress": None,  # street_address
	"postalCode": None,  # postal_code
	"l": None,  # town
	"st": None,  # state_province
	"co": None,  # country
}

ldap_user_pattern = r'.*[\]\["\:\;\|\=\+\*\?\<\>\/\\\,]'


def ldap_user_validator(value):
	def containsInvalidChars(s):
		return re.match(ldap_user_pattern, s) != None

	return not containsInvalidChars(value)


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
	distinguishedName = serializers.CharField(required=False)
	type = serializers.CharField(required=False)
	# First Name
	givenName = serializers.CharField(required=False)
	# Last Name
	sn = serializers.CharField(required=False)
	sAMAccountName = serializers.CharField(required=False)
	username = serializers.CharField(required=False)
	mail = serializers.CharField(required=False)
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
