################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.serializers.application_group
# Contains the Application Security Group Serializer

# ---------------------------------- IMPORTS --------------------------------- #
from rest_framework import serializers
from .ldap import DistinguishedNameField
from core.models.application import ApplicationSecurityGroup
from core.models.ldap_ref import LdapRef
from core.models.user import User
from core.ldap.connector import LDAPConnector
from django.core.exceptions import ObjectDoesNotExist
from core.decorators.intercept import is_ldap_backend_enabled
################################################################################


class ApplicationSecurityGroupSerializer(serializers.ModelSerializer):
	ldap_objects = serializers.ListField(child=DistinguishedNameField())

	class Meta:
		model = ApplicationSecurityGroup
		fields = "__all__"

	def create(self) -> ApplicationSecurityGroup:
		instance = super().create(self.validated_data)
		self.instance = instance
		return instance

	def save(self, **kwargs):
		if not isinstance(self.validated_data, dict):
			raise Exception(
				"validated_data is not of type dict, please use is_valid method"
				"first."
			)
		ldap_objects = self.validated_data.pop("ldap_objects", [])
		users = self.validated_data.pop("users", [])

		if not isinstance(self.instance, ApplicationSecurityGroup):
			self.create()

		asg = self.instance
		if not asg or not isinstance(self.instance, ApplicationSecurityGroup):
			raise Exception("No valid self.instance found.")

		asg.refresh_from_db()
		if users:
			self.validated_data["users"] = []
			_users_result = set()
			for user in users:
				if isinstance(user, User):
					_users_result.add(user.pk)
				elif isinstance(user, int):
					_users_result.add(user)
			self.validated_data["users"] = _users_result
		else:
			self.validated_data["users"] = asg.users.values_list(
				"id", flat=True
			)

		if is_ldap_backend_enabled():
			# Update LDAP References from Distinguished Names
			for distinguished_name in ldap_objects:
				# If it's already included, don't add it again
				if distinguished_name in asg.ldap_objects:
					continue

				try:
					asg.ldap_refs.add(
						LdapRef.objects.get(
							distinguished_name=distinguished_name
						).pk
					)
				except (LdapRef.DoesNotExist, ObjectDoesNotExist):
					with LDAPConnector(force_admin=True) as ldc:
						ldap_ref = LdapRef.get_instance_from_ldap(
							distinguished_name=distinguished_name,
							connection=ldc.connection,
						)
						if ldap_ref:
							ldap_ref.save()
							asg.ldap_refs.add(ldap_ref.pk)

			if self.instance:
				# Prune removed Refs
				refs_to_remove: set[int] = set()
				for ldap_ref in asg.ldap_refs.all():
					if not isinstance(ldap_ref, LdapRef):
						continue
					if ldap_ref.distinguished_name not in ldap_objects:
						refs_to_remove.add(ldap_ref.pk)
				for ldap_ref_pk in refs_to_remove:
					asg.ldap_refs.remove(ldap_ref_pk)
		super().save(**kwargs)
