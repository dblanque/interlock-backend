from rest_framework import serializers
from core.serializers.ldap import DistinguishedNameField
from django.core.validators import validate_email

class LDAPGroupSerializer(serializers.Serializer):
	# Common Name
	cn = serializers.CharField(required=False)
	# Distinguished Name
	distinguishedName = DistinguishedNameField()
	# Mail
	mail = serializers.CharField(
		allow_blank=True,
		required=False,
		validators=[validate_email],
	)
	email = serializers.CharField(
		allow_blank=True,
		required=False,
		validators=[validate_email],
	)
	groupType = serializers.IntegerField()
	groupScopes = serializers.IntegerField()
	member = serializers.ListField()
