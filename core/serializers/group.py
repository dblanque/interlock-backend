from rest_framework import serializers
from core.serializers.ldap import DistinguishedNameField
from django.core.validators import validate_email
from core.ldap.constants import (
	LOCAL_ATTR_GROUP_TYPE,
	LOCAL_ATTR_GROUP_SCOPE,
)

class LDAPGroupSerializer(serializers.Serializer):
	# Common Name
	common_name = serializers.CharField(required=False)
	# Distinguished Name
	distinguished_name = DistinguishedNameField(required=False)
	# Mail
	email = serializers.CharField(
		allow_blank=True,
		required=False,
		validators=[validate_email],
	)
	group_types = serializers.ListField(required=False)
	group_scopes = serializers.ListField(required=False)
	members = serializers.ListField(required=False, child=DistinguishedNameField())
	members_to_add = serializers.ListField(required=False, child=DistinguishedNameField())
	members_to_remove = serializers.ListField(required=False, child=DistinguishedNameField())

	def validate(self, data: dict):
		"""Handle extra validation"""
		group_types = data.get(LOCAL_ATTR_GROUP_TYPE, None)
		group_scopes = data.get(LOCAL_ATTR_GROUP_SCOPE, None)
		if not all(bool(x) for x in (group_types, group_scopes,)):
			raise serializers.ValidationError({
				LOCAL_ATTR_GROUP_TYPE:
					"Group Type updates require both %s and %s" % 
					(LOCAL_ATTR_GROUP_TYPE, LOCAL_ATTR_GROUP_SCOPE)
			})
		return data