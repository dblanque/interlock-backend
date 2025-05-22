from rest_framework import serializers
from core.serializers.ldap import DistinguishedNameField
from django.core.validators import validate_email
from core.ldap.types.group import LDAPGroupTypes
from core.constants.attrs import (
	LOCAL_ATTR_COMMON_NAME,
	LOCAL_ATTR_NAME,
	LOCAL_ATTR_GROUP_TYPE,
	LOCAL_ATTR_GROUP_SCOPE,
)


def group_type_validator(v: str):
	try:
		if v.upper().startswith("SCOPE_"):
			raise serializers.ValidationError(
				"Group Scope cannot be set in Group Type field.")

		LDAPGroupTypes[v]
	except serializers.ValidationError:
		raise
	except:
		raise serializers.ValidationError("Group Type is invalid")


def group_scope_validator(v: str):
	try:
		if v.upper().startswith("TYPE_"):
			raise serializers.ValidationError(
				"Group Type cannot be set in Group Scope field.")

		LDAPGroupTypes[v]
	except serializers.ValidationError:
		raise
	except:
		raise serializers.ValidationError("Group Scope is invalid")

class LDAPGroupSerializer(serializers.Serializer):
	# Common Name
	name = serializers.CharField(required=False)
	common_name = serializers.CharField(required=False)
	# Distinguished Name
	distinguished_name = DistinguishedNameField(required=False)
	# Mail
	email = serializers.CharField(
		allow_blank=True,
		required=False,
		validators=[validate_email],
	)
	group_types = serializers.ListField(
		required=False,
		child=serializers.CharField(validators=[group_type_validator]),
		max_length=2,
	)
	group_scopes = serializers.ListField(
		required=False,
		child=serializers.CharField(validators=[group_scope_validator]),
		max_length=1,
	)
	object_class = serializers.ListField(
		required=False, child=serializers.CharField()
	)
	object_category = serializers.CharField(required=False)
	object_security_id = serializers.CharField(required=False)
	object_relative_id = serializers.IntegerField(required=False)
	members = serializers.ListField(
		required=False, child=DistinguishedNameField()
	)
	members_to_add = serializers.ListField(
		required=False, child=DistinguishedNameField()
	)
	members_to_remove = serializers.ListField(
		required=False, child=DistinguishedNameField()
	)

	def validate(self, data: dict):
		"""Handle extra validation"""
		if LOCAL_ATTR_NAME in data:
			data[LOCAL_ATTR_COMMON_NAME] = data.get(LOCAL_ATTR_NAME)
		if LOCAL_ATTR_COMMON_NAME in data:
			data[LOCAL_ATTR_NAME] = data.get(LOCAL_ATTR_COMMON_NAME)
		group_types = data.get(LOCAL_ATTR_GROUP_TYPE, None)
		group_scopes = data.get(LOCAL_ATTR_GROUP_SCOPE, None)
		if not all(
			bool(x)
			for x in (
				group_types,
				group_scopes,
			)
		):
			raise serializers.ValidationError(
				{
					LOCAL_ATTR_GROUP_TYPE: "Group Type updates require both %s and %s"
					% (LOCAL_ATTR_GROUP_TYPE, LOCAL_ATTR_GROUP_SCOPE)
				}
			)
		return data
