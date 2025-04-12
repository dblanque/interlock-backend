################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.ldap.user
# Contains the Mixin for User related operations

# ---------------------------------- IMPORTS -----------------------------------#
### ViewSets
from rest_framework import viewsets

### Interlock
from core.ldap.adsi import search_filter_add
from core.config.runtime import RuntimeSettings
from core.ldap import user as ldap_user
from core.ldap import adsi as ldap_adsi
from core.ldap.types.account import LDAP_ACCOUNT_TYPES

### Models
from core.models import User
from core.models.ldap_object import LDAPObject, LDAPObjectOptions
from core.models.choices.log import (
	LOG_CLASS_USER,
	LOG_ACTION_CREATE,
	LOG_ACTION_READ,
	LOG_ACTION_UPDATE,
	LOG_ACTION_DELETE,
	LOG_EXTRA_UNLOCK,
	LOG_EXTRA_ENABLE,
	LOG_EXTRA_DISABLE,
	LOG_TARGET_ALL,
)
from core.ldap.connector import LDAPConnector
from core.views.mixins.logs import LogMixin
from ldap3 import Connection, MODIFY_DELETE, MODIFY_REPLACE
from ldap3.extend import (
	ExtendedOperationsRoot,
	StandardExtendedOperations,
	MicrosoftExtendedOperations,
)

### Mixins
from core.views.mixins.ldap.group import GroupViewMixin

### Exception Handling
from core.exceptions import base as exc_base, users as exc_user, ldap as exc_ldap
import traceback
import logging

### Others
from ldap3.utils.dn import safe_dn
from core.constants.user import UserViewsetFilterAttributeBuilder
from django.core.exceptions import ValidationError
from core.ldap.countries import LDAP_COUNTRIES
from core.ldap.adsi import LDAP_FILTER_NOT
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


class UserViewMixin(viewsets.ViewSetMixin):
	pass


class UserViewLDAPMixin(viewsets.ViewSetMixin):
	ldap_connection: Connection = None
	ldap_filter_object = None
	ldap_filter_attr = None
	filter_attr_builder = UserViewsetFilterAttributeBuilder

	def get_user_object_filter(self, username: str = None, email: str = None, xor=True, match_both=False):
		"""Gets LDAP User Object Filter

		Args:
			username (str, optional): Username. Defaults to None.
			email (str, optional): User Email. Defaults to None.
			xor (bool, optional): Use XOR, disallows searching by username and email at
				the same time. Defaults to True.
			match_both (bool, optional): Whether to match username and email in search
				filter (Uses LDAP_FILTER_AND instead of LDAP_FILTER_OR)

		Raises:
			ValueError: Raised if XOR is True and both username and email
				are Truthy or Falsy at the same time.

		Returns:
			str: LDAP Object Filter String
		"""
		if xor:
			if (not username and not email) or (username and email):
				raise ValueError("XOR Fail: Username OR Email required, single value allowed.")
			if match_both:
				raise ValueError("match_both and xor are incompatible options.")

		if match_both:
			id_filter_op = ldap_adsi.LDAP_FILTER_AND
		else:
			id_filter_op = ldap_adsi.LDAP_FILTER_OR

		# Class Filter Setup
		class_filter = search_filter_add(None, f"objectClass={RuntimeSettings.LDAP_AUTH_OBJECT_CLASS}")
		# Exclude Computer Accounts if settings allow it
		if RuntimeSettings.EXCLUDE_COMPUTER_ACCOUNTS:
			class_filter = search_filter_add(class_filter, f"objectClass=computer", negate_add=True)

		# User ID Filter Setup
		id_filter = None
		if username:
			id_filter = search_filter_add(
				id_filter,
				f"{RuntimeSettings.LDAP_AUTH_USER_FIELDS['username']}={username}",
				expression=id_filter_op
			)
		if email:
			id_filter = search_filter_add(
				id_filter,
				f"{RuntimeSettings.LDAP_AUTH_USER_FIELDS['email']}={email}",
				expression=id_filter_op
			)
		return search_filter_add(class_filter, id_filter)

	def get_user_object(
		self,
		username: str = None,
		email: str = None,
		attributes: list =None,
		object_class_filter=None,
	) -> Connection:
		"""Default: Search for the dn from a username string param.
		Can also be used to fetch entire object from that username string or filtered attributes.

		Args:
			username (str, optional): Required if no email is provided. Defaults to None.
			email (str, optional): Required if no username is provided. Defaults to None.
			attributes (list, optional): LDAP Attributes. Defaults to None.
			object_class_filter (str, optional): LDAP Search Filter. Defaults to None.

		Raises:
			ValidationError: If username and email are Falsy.

		Returns the first matching entry.
		"""
		if not username and not email:
			raise ValidationError(
				"username or email are required for get_user_object call.")

		if not attributes:
			attributes = [
				RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"],
				"distinguishedName"
			]
		if not object_class_filter:
			object_class_filter = self.get_user_object_filter(username=username, email=email, xor=False)

		self.ldap_connection.search(
			search_base=RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
			search_filter=object_class_filter,
			attributes=attributes,
		)
		return self.get_user_entry(username=username, email=email)
	
	def get_user_entry(self, username = None, email = None):
		if not username and not email:
			raise ValueError("username or email must be specified in get_user_entry call.")
		if not self.ldap_connection.entries:
			return

		_username_field = RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"]
		_email_field = RuntimeSettings.LDAP_AUTH_USER_FIELDS["email"]
		for entry in self.ldap_connection.entries:
			if username and email:
				if (
					getattr(entry, _username_field) == username and
					getattr(entry, _email_field) == email
				):
					return entry
			elif username:
				if getattr(entry, _username_field) == username:
					return entry
			elif email:
				if getattr(entry, _email_field) == email:
					return entry

	def get_group_attributes(self, groupDn, idFilter=None, classFilter=None):
		attributes = ["objectSid"]
		if idFilter is None:
			idFilter = "distinguishedName=" + groupDn
		if classFilter is None:
			classFilter = "objectClass=group"
		object_class_filter = ""
		object_class_filter = search_filter_add(object_class_filter, classFilter)
		object_class_filter = search_filter_add(object_class_filter, idFilter)
		group = LDAPObject(
			connection=self.ldap_connection,
			ldap_filter=object_class_filter,
			ldap_attrs=attributes,
		)
		return group.attributes

	def ldap_user_list(self) -> dict:
		"""
		Returns dictionary with the following keys:
		* headers: Headers list() for the front-end data-table
		* users: Users dict()
		"""
		user_list = []

		# Exclude Computer Accounts if settings allow it
		if RuntimeSettings.EXCLUDE_COMPUTER_ACCOUNTS:
			self.ldap_filter_object = ldap_adsi.search_filter_add(
				self.ldap_filter_object, "objectClass=computer", negate_add=True
			)

		# Exclude Contacts
		self.ldap_filter_object = ldap_adsi.search_filter_add(
			self.ldap_filter_object, "objectClass=contact", negate_add=True
		)

		self.ldap_connection.search(
			RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
			self.ldap_filter_object,
			attributes=self.ldap_filter_attr,
		)
		user_entry_list = self.ldap_connection.entries

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_USER,
			log_target=LOG_TARGET_ALL,
		)

		# Remove attributes to return as table headers
		valid_attributes: list = self.ldap_filter_attr
		remove_attributes = ["distinguishedName", "userAccountControl", "displayName"]
		for attr in remove_attributes:
			if attr in valid_attributes:
				valid_attributes.remove(attr)

		valid_attributes.append("is_enabled")

		for user in user_entry_list:
			# Uncomment line below to see all attributes in user object
			# print(dir(user))

			# For each attribute in user object attributes
			user_dict = {}
			for attr_key in dir(user):
				if attr_key in valid_attributes:
					str_key = str(attr_key)
					str_value = str(getattr(user, attr_key))
					if str_value == "[]":
						user_dict[str_key] = ""
					else:
						user_dict[str_key] = str_value
				if attr_key == RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"]:
					user_dict["username"] = str_value

			# Add entry DN to response dictionary
			user_dict["distinguishedName"] = user.entry_dn

			# Check if user is disabled
			user_dict["is_enabled"] = True
			try:
				if ldap_adsi.list_user_perms(
					user=user, perm_search=ldap_adsi.LDAP_UF_ACCOUNT_DISABLE
				):
					user_dict["is_enabled"] = False
			except Exception as e:
				print(e)
				print(f"Could not get user status for DN: {user_dict['distinguishedName']}")

			user_list.append(user_dict)
		result = {}
		result["users"] = user_list
		result["headers"] = valid_attributes
		return result

	def ldap_user_insert(
		self,
		user_data: dict,
		exclude_keys: list = None,
		return_exception: bool = True,
		key_mapping: dict = None,
	) -> str:
		"""
		Returns User LDAP Distinguished Name on successful insert.
		"""
		# TODO Check by authUsernameIdentifier and CN
		# TODO Add customizable default user path
		try:
			user_path = user_data.pop("path", None)
			if user_path:
				user_dn = f"CN={user_data['username']},{user_path}"
			else:
				user_dn = (
					f"CN={user_data['username']},CN=Users,{RuntimeSettings.LDAP_AUTH_SEARCH_BASE}"
				)
			user_dn = safe_dn(dn=user_dn)
		except:
			raise exc_user.UserDNPathException

		parsed_user_attrs = {}
		permission_list = user_data.pop("permission_list", [])
		if permission_list and isinstance(permission_list, list):
			parsed_user_attrs["userAccountControl"] = ldap_adsi.calc_permissions(
				permission_list=permission_list
			)
		else:
			parsed_user_attrs["userAccountControl"] = ldap_adsi.calc_permissions(
				[
					ldap_adsi.LDAP_UF_NORMAL_ACCOUNT,
				]
			)
		parsed_user_attrs[RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"]] = str(
			user_data["username"]
		).lower()
		parsed_user_attrs["objectClass"] = ["top", "person", "organizationalPerson", "user"]
		parsed_user_attrs["userPrincipalName"] = (
			f"{user_data['username']}@{RuntimeSettings.LDAP_DOMAIN}"
		)

		if not exclude_keys:
			exclude_keys = [
				"password",
				"passwordConfirm",
				"path",
				"permission_list",  # This array was parsed and calculated, we need to ensure it's not looped over
				"distinguishedName",  # We don't want the front-end generated DN
				"username",  # LDAP Uses sAMAccountName
			]

		for key in user_data:
			if key in exclude_keys or len(str(user_data[key])) <= 0:
				continue

			logger.debug("Key in data: " + key)
			logger.debug("Value for key above: " + user_data[key])
			if key_mapping and key in key_mapping.values():
				# In the event of using a mapping translation (e.g.: bulk import from csv)
				for _k, _mapped_k in key_mapping.items():
					if _mapped_k == key:
						ldap_key = _k
						break
				parsed_user_attrs[ldap_key] = user_data[key]
			else:
				# Normal behavior
				parsed_user_attrs[key] = user_data[key]

		logger.debug(f"Creating user in DN Path: {user_dn}")
		try:
			self.ldap_connection.add(
				user_dn, RuntimeSettings.LDAP_AUTH_OBJECT_CLASS, attributes=parsed_user_attrs
			)
		except Exception as e:
			logger.error(e)
			logger.error(f"Could not create User: {user_dn}")
			if return_exception:
				raise exc_user.UserCreate(data={"ldap_response": self.ldap_connection.result})
			return None

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_CREATE,
			log_target_class=LOG_CLASS_USER,
			log_target=user_data["username"],
		)

		return user_dn

	def ldap_user_update(
		self, user_dn: str, user_name: str, user_data: dict, permissions_list: list = None
	) -> LDAPConnector:
		"""Updates LDAP User with provided data

		Returns:
			ldap3.Connection
		"""
		connection_entries = self.ldap_connection.entries

		################# START NON-STANDARD ARGUMENT UPDATES ##################
		if permissions_list:
			if ldap_adsi.LDAP_UF_LOCKOUT in permissions_list:
				# Default is 30 Minutes
				user_data["lockoutTime"] = 30
			try:
				new_permissions_int = ldap_adsi.calc_permissions(permissions_list)
			except:
				raise exc_user.UserPermissionError

			logger.debug("Located in: %s.update", __name__)
			logger.debug("New Permission Integer (cast to String): %s", str(new_permissions_int))
			user_data["userAccountControl"] = new_permissions_int
		else:
			user_data["userAccountControl"] = ldap_adsi.LDAP_PERMS[
				ldap_adsi.LDAP_UF_NORMAL_ACCOUNT
			]["value"]

		user_country = user_data.get(ldap_user.COUNTRY, None)
		if user_country:
			try:
				# Set numeric country code (DCC Standard)
				user_data[ldap_user.COUNTRY_DCC] = LDAP_COUNTRIES[user_country]["dccCode"]
				# Set ISO Country Code
				user_data[ldap_user.COUNTRY_ISO] = LDAP_COUNTRIES[user_country]["isoCode"]
			except Exception as e:
				logger.exception(e)
				raise exc_user.UserCountryUpdateError

		# Catch rare front-end mutation exception
		if "groupsToAdd" in user_data and "groupsToRemove" in user_data:
			if (
				user_data["groupsToAdd"] == user_data["groupsToRemove"] and user_data["groupsToAdd"]
			) != []:
				raise exc_user.BadGroupSelection

		# Group Add
		groupsToAdd = user_data.pop("groupsToAdd", None)
		if groupsToAdd:
			self.ldap_connection.extend.microsoft.add_members_to_groups(user_dn, groupsToAdd)

		# Group Remove
		groupsToRemove = user_data.pop("groupsToRemove", None)
		if groupsToRemove:
			self.ldap_connection.extend.microsoft.remove_members_from_groups(
				user_dn, groupsToRemove
			)

		user_data.pop("memberOfObjects", None)
		user_data.pop("memberOf", None)

		################### START STANDARD ARGUMENT UPDATES ####################
		operation = None
		for key in user_data:
			try:
				if key in connection_entries[0].entry_attributes and user_data[key] == "":
					operation = MODIFY_DELETE
					self.ldap_connection.modify(
						user_dn,
						{key: [(operation), []]},
					)
				elif user_data[key] != "":
					operation = MODIFY_REPLACE
					if isinstance(user_data[key], list):
						self.ldap_connection.modify(
							user_dn,
							{key: [(operation, user_data[key])]},
						)
					else:
						self.ldap_connection.modify(
							user_dn,
							{key: [(operation, [user_data[key]])]},
						)
				else:
					logger.info("No suitable operation for attribute " + key)
					pass
			except Exception as e:
				logger.exception(e)
				logger.error(
					"Unable to update user '%s' with attribute '%s'", str(user_name), str(key)
				)
				logger.error("Attribute Value: " + str(user_data[key]))
				logger.error("Attribute Type: " + str(type(user_data[key])))
				if operation is not None:
					logger.error("Operation Type: " + str(operation))
				raise exc_user.UserUpdateError

		logger.debug(self.ldap_connection.result)

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=user_name,
		)

		try:
			django_user = User.objects.get(username=user_name)
		except:
			django_user = None
			pass

		if django_user:
			for key in RuntimeSettings.LDAP_AUTH_USER_FIELDS:
				mapped_key = RuntimeSettings.LDAP_AUTH_USER_FIELDS[key]
				if mapped_key in user_data:
					setattr(django_user, key, user_data[mapped_key])
				if "mail" not in user_data:
					django_user.email = None
			django_user.save()
		return self.ldap_connection

	def ldap_set_password(
		self, user_dn: str, user_pwd_new: str, user_pwd_old: str = None, set_by_admin=False
	) -> LDAPConnector:
		"""
		### Sets the LDAP User's Password with Microsoft Extended LDAP Commands
		Returns the used LDAP Connection
		### ! Microsoft AD Servers do not allow password changing without LDAPS
		"""
		# Type hinting defs
		extended_operations: ExtendedOperationsRoot = self.ldap_connection.extend
		eo_standard: StandardExtendedOperations = extended_operations.standard
		eo_microsoft: MicrosoftExtendedOperations = extended_operations.microsoft

		if not isinstance(user_pwd_new, str):
			raise TypeError("user_pwd_new must be of type str.")
		if not set_by_admin and not isinstance(user_pwd_old, str):
			raise TypeError("user_pwd_old must be of type str.")

		# Validation
		if not set_by_admin and not user_pwd_old:
			raise exc_user.UserPasswordsDontMatch()

		# Set kwargs
		pwd_kwargs = {"new_password": user_pwd_new}
		if user_pwd_old:
			pwd_kwargs["old_password"] = user_pwd_old

		try:
			# If available use standard password extended operation
			if "1.3.6.1.4.1.4203.1.11.1" in self.ldap_connection.server.info.supported_extensions:
				return eo_standard.modify_password(user=user_dn, **pwd_kwargs)
			else:
				# Otherwise attempt to change password directly with Microsoft Extended Op.
				return eo_microsoft.modify_password(user=user_dn, **pwd_kwargs)
		except Exception as e:
			logger.exception(e)
			logger.error(f"Could not update password for User DN: {user_dn}")
			data = {"ldap_response": self.ldap_connection.result}
			raise exc_user.UserUpdateError(data=data)

	def ldap_user_exists(
			self,
			username: str = None,
			email: str = None,
			return_exception: bool = True
		) -> bool:
		"""Checks if LDAP User Exists on Directory

		Args:
			username (str, optional): Required if no email is provided. Defaults to None.
			email (str, optional): Required if no username is provided. Defaults to None.
			return_exception (bool, optional): Whether to return exception when a user
				entry is found. Defaults to True.

		Raises:
			ValidationError: Returned if no email and username are provided.
			exc_ldap.LDAPObjectExists: Returned if return_exception is True.

		Returns:
			bool
		"""

		# Send LDAP Query for user being created to see if it exists
		if not username and not email:
			raise ValidationError(
				"username or email args are required for ldap_user_exists call.")
		ldap_attributes = [
			RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"],
			"distinguishedName",
			RuntimeSettings.LDAP_AUTH_USER_FIELDS["email"],
		]
		self.get_user_object(username=username, email=email, attributes=ldap_attributes)
		entry_by_email = self.get_user_entry(email=email) if email else None

		# If entries is not falsy, return Exception or True
		if self.ldap_connection.entries:
			if return_exception:
				if entry_by_email:
					_code = "user_email_exists"
				else:
					_code = "user_exists"
				raise exc_ldap.LDAPObjectExists(data={"code": _code})
			else:
				return True
		return False

	def ldap_user_fetch(self, user_search):
		self.ldap_filter_object = f"(objectClass={RuntimeSettings.LDAP_AUTH_OBJECT_CLASS})"
		if not self.ldap_filter_attr:
			self.ldap_filter_attr = self.filter_attr_builder(RuntimeSettings).get_fetch_attrs()

		# Exclude Computer Accounts if settings allow it
		if RuntimeSettings.EXCLUDE_COMPUTER_ACCOUNTS == True:
			self.ldap_filter_object = ldap_adsi.search_filter_add(
				self.ldap_filter_object, "objectClass=computer", negate_add=True
			)

		# Add filter for username
		self.ldap_filter_object = ldap_adsi.search_filter_add(
			self.ldap_filter_object,
			f"{RuntimeSettings.LDAP_AUTH_USER_FIELDS['username']}={user_search}",
		)
		ldap_object_options: LDAPObjectOptions = {
			"connection": self.ldap_connection,
			"ldap_filter": self.ldap_filter_object,
			"ldap_attrs": self.ldap_filter_attr,
		}

		user_obj = LDAPObject(**ldap_object_options)
		user_entry = user_obj.entry
		user_dict = user_obj.attributes

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_USER,
			log_target=user_search,
		)

		memberOfObjects = []
		if "memberOf" in self.ldap_filter_attr and "memberOf" in user_dict:
			memberOf = user_dict.pop("memberOf")
			if isinstance(memberOf, list):
				for g in memberOf:
					memberOfObjects.append(self.get_group_attributes(g))
			else:
				g = memberOf
				memberOfObjects.append(self.get_group_attributes(g))

		### Also add default Users Group to be available as Selectable PID
		if "primaryGroupID" in self.ldap_filter_attr:
			memberOfObjects.append(GroupViewMixin.getGroupByRID(user_dict["primaryGroupID"]))

		if len(memberOfObjects) > 0:
			user_dict["memberOfObjects"] = memberOfObjects
		else:
			raise exc_user.UserGroupsFetchError

		del memberOfObjects

		if "userAccountControl" in self.ldap_filter_attr:
			# Check if user is disabled
			user_dict["is_enabled"] = True
			try:
				if ldap_adsi.list_user_perms(
					user=user_entry, perm_search="LDAP_UF_ACCOUNT_DISABLE", user_is_object=False
				):
					user_dict["is_enabled"] = False
			except Exception as e:
				print(e)
				print(user_dict["distinguishedName"])

			# Check if user is disabled
			try:
				userPermissions = ldap_adsi.list_user_perms(
					user=user_entry, perm_search=None, user_is_object=False
				)
				user_dict["permission_list"] = userPermissions
			except Exception as e:
				print(e)
				print(user_dict["distinguishedName"])

		if "sAMAccountType" in self.ldap_filter_attr:
			# Replace sAMAccountType Value with String Corresponding
			userAccountType = int(user_dict["sAMAccountType"])
			for accountType in LDAP_ACCOUNT_TYPES:
				accountTypeValue = LDAP_ACCOUNT_TYPES[accountType]
				if accountTypeValue == userAccountType:
					user_dict["sAMAccountType"] = accountType
		return user_dict

	def ldap_user_change_status(self, user_object, target_state: bool):
		affected_user = user_object["username"]
		self.ldap_filter_object = ""

		# Exclude Computer Accounts if settings allow it
		if RuntimeSettings.EXCLUDE_COMPUTER_ACCOUNTS == True:
			self.ldap_filter_object = ldap_adsi.search_filter_add(
				self.ldap_filter_object, "objectClass=computer", negate_add=True
			)

		# Add filter for username
		self.ldap_filter_object = ldap_adsi.search_filter_add(
			self.ldap_filter_object,
			f"{RuntimeSettings.LDAP_AUTH_USER_FIELDS['username']}={affected_user}",
		)

		self.ldap_connection.search(
			RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
			self.ldap_filter_object,
			attributes=self.ldap_filter_attr,
		)

		user = self.ldap_connection.entries
		dn = str(user[0].distinguishedName)
		permList = ldap_adsi.list_user_perms(user=user[0], user_is_object=False)

		if dn == RuntimeSettings.LDAP_AUTH_CONNECTION_USER_DN:
			raise exc_user.UserAntiLockout

		try:
			if target_state is True:
				newPermINT = ldap_adsi.calc_permissions(
					permList, perm_remove="LDAP_UF_ACCOUNT_DISABLE"
				)
			else:
				newPermINT = ldap_adsi.calc_permissions(
					permList, perm_add="LDAP_UF_ACCOUNT_DISABLE"
				)
		except:
			print(traceback.format_exc())
			self.ldap_connection.unbind()
			raise exc_user.UserPermissionError

		self.ldap_connection.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [newPermINT])]})

		try:
			django_user = User.objects.get(username=affected_user)
		except:
			django_user = None
			pass

		if django_user:
			django_user.is_enabled = target_state
			django_user.save()

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=affected_user,
			message=LOG_EXTRA_ENABLE if target_state else LOG_EXTRA_DISABLE,
		)

		logger.debug("Located in: " + __name__ + ".disable")
		logger.debug(self.ldap_connection.result)
		return self.ldap_connection

	def ldap_user_unlock(self, user_object):
		username = user_object["username"]
		# If data request for deletion has user DN
		if "distinguishedName" in user_object.keys() and user_object["distinguishedName"] != "":
			logger.debug("Updating with distinguishedName obtained from front-end")
			logger.debug(user_object["distinguishedName"])
			user_dn = user_object["distinguishedName"]
		# Else, search for username dn
		else:
			logger.debug("Updating with user dn search method")
			user_entry = self.get_user_object(username)
			user_dn = str(user_entry.distinguishedName)
			logger.debug(user_dn)

		if not user_dn or user_dn == "":
			self.ldap_connection.unbind()
			raise exc_user.UserDoesNotExist

		self.ldap_connection.extend.microsoft.unlock_account(user_dn)
		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=username,
			message=LOG_EXTRA_UNLOCK,
		)
		return self.ldap_connection

	def ldap_user_delete(self, user_object):
		if RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"] in user_object:
			username = user_object[RuntimeSettings.LDAP_AUTH_USER_FIELDS["username"]]
		elif "username" in user_object:
			username = user_object["username"]
		else:
			raise exc_base.CoreException

		# If data request for deletion has user DN
		if "distinguishedName" in user_object.keys() and user_object["distinguishedName"] != "":
			logger.debug("Deleting with distinguishedName obtained from front-end")
			logger.debug(user_object["distinguishedName"])
			user_dn = user_object["distinguishedName"]
			if not user_dn or user_dn == "":
				self.ldap_connection.unbind()
				raise exc_user.UserDoesNotExist
			try:
				self.ldap_connection.delete(user_dn)
			except Exception as e:
				self.ldap_connection.unbind()
				print(e)
				data = {"ldap_response": self.ldap_connection.result}
				raise exc_base.CoreException(data=data)
		# Else, search for username dn
		else:
			logger.debug("Deleting with user dn search method")
			user_entry = self.get_user_object(username)
			user_dn = str(user_entry.distinguishedName)
			logger.debug(user_dn)

			if not user_dn or user_dn == "":
				self.ldap_connection.unbind()
				raise exc_user.UserDoesNotExist
			try:
				self.ldap_connection.delete(user_dn)
			except Exception as e:
				self.ldap_connection.unbind()
				print(e)
				data = {"ldap_response": self.ldap_connection.result}
				raise exc_base.CoreException(data=data)

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_DELETE,
			log_target_class=LOG_CLASS_USER,
			log_target=username,
		)

		return self.ldap_connection
