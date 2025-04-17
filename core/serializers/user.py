import re
from rest_framework import serializers
from core.models.application import User

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
		fields = ("username", "first_name", "last_name", "email", "password", "passwordConfirm")

	def validate_password_confirm(self, data=None, raise_exc=True):
		if data is None and not hasattr(self, "data"):
			return False
		elif data is None:
			data = self.data
		for field in ("password", "passwordConfirm"):
			if not field in data:
				if raise_exc is True:
					raise serializers.ValidationError(f"{field} is required.")
				else:
					return False
		_pwd: str = data["password"]
		_pwd_confirm: str = data.pop("passwordConfirm")
		if _pwd != _pwd_confirm:
			if raise_exc is True:
				raise serializers.ValidationError("Passwords do not match.")
			else:
				return False
		return True

LDAP_DATE_FORMAT = '%Y%m%d%H%M%S.%fZ'
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
		input_formats=[LDAP_DATE_FORMAT, 'iso-8601'],
		required=False
	)
	whenChanged = serializers.DateTimeField(
		format=LDAP_DATE_FORMAT,
		input_formats=[LDAP_DATE_FORMAT, 'iso-8601'],
		required=False
	)
	lastLogonTimestamp = serializers.DateTimeField(
		format=LDAP_DATE_FORMAT,
		input_formats=[LDAP_DATE_FORMAT, 'iso-8601'],
		required=False
	)
	accountExpires = serializers.DateTimeField(
		format=LDAP_DATE_FORMAT,
		input_formats=[LDAP_DATE_FORMAT, 'iso-8601'],
		required=False
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
