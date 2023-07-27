################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.user
# Contains the Mixin for User related operations

#---------------------------------- IMPORTS -----------------------------------#
### ViewSets
from rest_framework import viewsets

### Interlock
from interlock_backend.ldap.adsi import search_filter_add
from interlock_backend.ldap.constants_cache import *
from interlock_backend.ldap import adsi as ldap_adsi
from interlock_backend.ldap.user_flags import LDAP_UF_NORMAL_ACCOUNT
from interlock_backend.ldap.accountTypes import LDAP_ACCOUNT_TYPES

### Models
from core.models import User
from core.models.ldapObject import LDAPObject
from interlock_backend.ldap.connector import LDAPConnector
from core.models.log import logToDB
from ldap3 import (
	MODIFY_ADD,
	MODIFY_DELETE,
	MODIFY_INCREMENT,
	MODIFY_REPLACE
)

### Mixins
from .group import GroupViewMixin

### Exception Handling
from core.exceptions import (
	base as exc_base,
	users as exc_user, 
	ldap as exc_ldap
)
import traceback
import logging

### Others
from interlock_backend.ldap.countries import LDAP_COUNTRIES
################################################################################

logger = logging.getLogger(__name__)

class UserViewMixin(viewsets.ViewSetMixin):
	pass

class UserViewLDAPMixin(viewsets.ViewSetMixin):
	ldap_connection = None
	ldap_filter_object = None
	ldap_filter_attr = None

	def get_user_object_filter(self, username):
		filter = "(objectclass=" + LDAP_AUTH_OBJECT_CLASS + ")"

		# Exclude Computer Accounts if settings allow it
		if EXCLUDE_COMPUTER_ACCOUNTS == True:
			filter = search_filter_add(filter, "!(objectclass=computer)")

		# Add filter for username
		filter = search_filter_add(
			filter,
			LDAP_AUTH_USER_FIELDS["username"] + "=" + username
			)
		return filter

	def get_user_object(self, username, attributes=[LDAP_AUTH_USER_FIELDS["username"], 'distinguishedName'], object_class_filter=None):
		""" Default: Search for the dn from a username string param.
		
		Can also be used to fetch entire object from that username string or filtered attributes.

		ARGUMENTS

		:username: (String) -- User to be searched

		:attributes: (String || List) -- Attributes to return in entry, default are DN and username Identifier

		e.g.: sAMAccountName

		:objectClassFilter: (String) -- Default is obtained from settings

		Returns the connection.
		"""
		if object_class_filter == None:
			object_class_filter = self.get_user_object_filter(username)

		self.ldap_connection.search(
			LDAP_AUTH_SEARCH_BASE, 
			object_class_filter, 
			attributes=attributes
		)

		return self.ldap_connection

	def get_group_attributes(self, groupDn, idFilter=None, classFilter=None):
		attributes = [ 'objectSid' ]
		if idFilter is None:
			idFilter =  "distinguishedName=" + groupDn
		if classFilter is None:
			classFilter = "objectClass=group"
		object_class_filter = ""
		object_class_filter = search_filter_add(object_class_filter, classFilter)
		object_class_filter = search_filter_add(object_class_filter, idFilter)
		args = {
			"connection": self.ldap_connection,
			"ldapFilter": object_class_filter,
			"ldapAttributes": attributes
		}
		group = LDAPObject(**args)
		return group.attributes

	def calc_perms_from_list(self, permission_list=list()):
		user_perms = 0
		if len(permission_list) > 0:
			# Add permissions selected in user creation
			for perm in permission_list:
				permValue = int(ldap_adsi.LDAP_PERMS[perm]['value'])
				try:
					user_perms += permValue
					logger.debug("Located in: "+__name__+".insert")
					logger.debug("Permission Value added (cast to string): " + str(permValue))
				except Exception as error:
					# If there's an error unbind the connectioön and print traceback
					self.ldap_connection.unbind()
					print(traceback.format_exc())
					raise exc_user.UserPermissionError # Return error code to client

		# Add Normal Account permission to list
		user_perms += ldap_adsi.LDAP_PERMS['LDAP_UF_NORMAL_ACCOUNT']['value']
		logger.debug("Final User Permissions Value: " + str(user_perms))
		return user_perms

	def ldap_user_list(self) -> dict:
		"""
		Returns dictionary with the following keys:
		* headers: Headers list() for the front-end data-table
		* users: Users dict()
		"""
		user_list = list()

		# Exclude Computer Accounts if settings allow it
		if EXCLUDE_COMPUTER_ACCOUNTS == True:
			self.ldap_filter_object = ldap_adsi.search_filter_add(self.ldap_filter_object, "!(objectclass=computer)")
		
		# Exclude Contacts
		self.ldap_filter_object = ldap_adsi.search_filter_add(self.ldap_filter_object, "!(objectclass=contact)")

		try:
			self.ldap_connection.search(
				LDAP_AUTH_SEARCH_BASE,
				self.ldap_filter_object,
				attributes=self.ldap_filter_attr
			)
		except:            
			self.ldap_connection.unbind()
			raise
		userList = self.ldap_connection.entries

		if LDAP_LOG_READ == True:
			# Log this action to DB
			logToDB(
				user_id=self.request.user.id,
				actionType="READ",
				objectClass="USER",
				affectedObject="ALL"
			)

		# Remove attributes to return as table headers
		valid_attributes = self.ldap_filter_attr
		remove_attributes = [ 
			'distinguishedName', 
			'userAccountControl', 
			'displayName' 
		]
		for attr in remove_attributes:
			if attr in valid_attributes:
				valid_attributes.remove(str(attr))

		valid_attributes.append('is_enabled')

		for user in userList:
			# Uncomment line below to see all attributes in user object
			# print(dir(user))

			# For each attribute in user object attributes
			user_dict = {}
			for attr_key in dir(user):
				if attr_key in valid_attributes:
					str_key = str(attr_key)
					str_value = str(getattr(user,attr_key))
					if str_value == "[]":
						user_dict[str_key] = ""
					else:
						user_dict[str_key] = str_value
				if attr_key == LDAP_AUTH_USER_FIELDS["username"]:
					user_dict['username'] = str_value

			# Add entry DN to response dictionary
			user_dict['distinguishedName'] = user.entry_dn

			# Check if user is disabled
			user_dict['is_enabled'] = True
			try:
				if ldap_adsi.list_user_perms(user=user, perm_search="LDAP_UF_ACCOUNT_DISABLE"):
					user_dict['is_enabled'] = False
			except Exception as e:
				print(e)
				print(f"Could not get user status for DN: {user_dict['distinguishedName']}")

			user_list.append(user_dict)
		result = dict()
		result["users"] = user_list
		result["headers"] = valid_attributes
		return result
	
	def ldap_user_insert(
			self,
			user_data,
			exclude_keys: list = None,
			return_exception: bool = True,
			key_mapping: dict = None
		) -> str:
		"""
		Returns User LDAP Distinguished Name on successful insert.
		"""
		# TODO Check by authUsernameIdentifier and CN
		# TODO Add customizable default user path
		try:
			if 'path' in user_data and user_data['path'] is not None and user_data['path'] != "":
				user_dn = 'CN='+user_data['username']+','+user_data['path']
				user_data.pop('path')
			else:
				user_dn = 'CN='+user_data['username']+',OU=Users,'+LDAP_AUTH_SEARCH_BASE
		except:
			raise exc_user.UserDNPathException


		arguments = dict()
		if 'permission_list' in user_data:
			arguments['userAccountControl'] = self.calc_perms_from_list(user_data['permission_list'])
		else:
			arguments['userAccountControl'] = self.calc_perms_from_list()
		arguments[LDAP_AUTH_USER_FIELDS["username"]] = str(user_data['username']).lower()
		arguments['objectClass'] = ['top', 'person', 'organizationalPerson', 'user']
		arguments['userPrincipalName'] = user_data['username'] + '@' + LDAP_DOMAIN

		if not exclude_keys:
			exclude_keys = [
				'password', 
				'passwordConfirm',
				'path',
				'permission_list', # This array was parsed and calculated, then changed to userAccountControl
				'distinguishedName', # We don't want the front-end generated DN
				'username' # LDAP Uses sAMAccountName
			]

		for key in user_data:
			if key not in exclude_keys and len(str(user_data[key])) > 0:
				logger.debug("Key in data: " + key)
				logger.debug("Value for key above: " + user_data[key])
				if key_mapping and key in key_mapping.values():
					for lk in key_mapping: 
						if key_mapping[lk] == key:
							ldap_key = lk
							break
					arguments[ldap_key] = user_data[key]
				else:
					arguments[key] = user_data[key]

		logger.debug(f'Creating user in DN Path: {user_dn}')
		try:
			self.ldap_connection.add(user_dn, LDAP_AUTH_OBJECT_CLASS, attributes=arguments)
		except Exception as e:
			logger.error(e)
			logger.error(f'Could not create User: {user_dn}')
			if return_exception:
				self.ldap_connection.unbind()
				user_data = {
					"ldap_response": self.ldap_connection.result
				}
				raise exc_user.UserCreate(data=user_data)
			return None

		if LDAP_LOG_CREATE == True:
			# Log this action to DB
			logToDB(
				user_id=self.request.user.id,
				actionType="CREATE",
				objectClass="USER",
				affectedObject=user_data['username']
			)

		return user_dn
	
	def ldap_user_update(
			self,
			user_dn: str,
			user_name: str,
			user_data: dict,
			permissions_list: list = None
		) -> LDAPConnector:
		"""
		### Updates LDAP User with provided data
		Returns the used LDAP Connection
		"""
		connection_entries = self.ldap_connection.entries

		if 'LDAP_UF_LOCKOUT' in permissions_list:
			# Default is 30 Minutes
			user_data['lockoutTime'] = 30 
		
		################# START NON-STANDARD ARGUMENT UPDATES ##################
		if permissions_list:
			try:
				new_permissions_int = ldap_adsi.calc_permissions(permissions_list)
			except:
				print(traceback.format_exc())
				self.ldap_connection.unbind()
				raise exc_user.UserPermissionError

			logger.debug("Located in: "+__name__+".update")
			logger.debug("New Permission Integer (cast to String):" + str(new_permissions_int))
			user_data['userAccountControl'] = new_permissions_int
		else:
			user_data['userAccountControl'] = LDAP_UF_NORMAL_ACCOUNT

		if 'co' in user_data and user_data['co'] != "" and user_data['co'] != 0:
			try:
				# Set numeric country code (DCC Standard)
				user_data['countryCode'] = LDAP_COUNTRIES[user_data['co']]['dccCode']
				# Set ISO Country Code
				user_data['c'] = LDAP_COUNTRIES[user_data['co']]['isoCode']
			except Exception as e:
				self.ldap_connection.unbind()
				print(user_data)
				print(e)
				raise exc_user.UserCountryUpdateError

		# Catch rare occurring exception
		if 'groupsToAdd' in user_data and 'groupsToRemove' in user_data:
			if user_data['groupsToAdd'] == user_data['groupsToRemove'] and user_data['groupsToAdd'] != list():
				self.ldap_connection.unbind()
				print(user_data)
				raise exc_user.BadGroupSelection

		if 'groupsToAdd' in user_data:
			groupsToAdd = user_data.pop('groupsToAdd')
			if len(groupsToAdd) > 0:
				self.ldap_connection.extend.microsoft.add_members_to_groups(user_dn, groupsToAdd)
		if 'groupsToRemove' in user_data:
			groupsToRemove = user_data.pop('groupsToRemove')
			if len(groupsToRemove) > 0:
				self.ldap_connection.extend.microsoft.remove_members_from_groups(user_dn, groupsToRemove)

		if 'memberOfObjects' in user_data:
			user_data.pop('memberOfObjects')
		if 'memberOf' in user_data:
			user_data.pop('memberOf')

		################### START STANDARD ARGUMENT UPDATES ####################
		arguments = dict()
		operation = None
		for key in user_data:
				try:
					if key in connection_entries[0].entry_attributes and user_data[key] == "":
						operation = MODIFY_DELETE
						self.ldap_connection.modify(
							user_dn,
							{key: [( operation ), []]},
						)
					elif user_data[key] != "":
						operation = MODIFY_REPLACE
						if isinstance(user_data[key], list):
							self.ldap_connection.modify(
								user_dn,
								{key: [( operation, user_data[key])]},
							)
						else:
							self.ldap_connection.modify(
								user_dn,
								{key: [( operation, [ user_data[key] ])]},
							)
					else:
						logger.info("No suitable operation for attribute " + key)
						pass
				except:
					print(traceback.format_exc())
					logger.warn("Unable to update user '" + str(user_name) + "' with attribute '" + str(key) + "'")
					logger.warn("Attribute Value:" + str(user_data[key]))
					if operation is not None:
						logger.warn("Operation Type: " + str(operation))
					self.ldap_connection.unbind()
					raise exc_user.UserUpdateError

		logger.debug(self.ldap_connection.result)

		if LDAP_LOG_UPDATE == True:
			# Log this action to DB
			logToDB(
				user_id=self.request.user.id,
				actionType="UPDATE",
				objectClass="USER",
				affectedObject=user_name
			)

		try:
			django_user = User.objects.get(username=user_name)
		except:
			django_user = None
			pass

		if django_user:
			for key in LDAP_AUTH_USER_FIELDS:
				mapped_key = LDAP_AUTH_USER_FIELDS[key]
				if mapped_key in user_data:
					setattr(django_user, key, user_data[mapped_key])
				if 'mail' not in user_data:
					django_user.email = None
			django_user.save()
		return self.ldap_connection

	def set_ldap_password(self, user_dn: str, user_pwd: str) -> LDAPConnector:
		"""
		### Sets the LDAP User's Password with Microsoft Extended LDAP Commands
		Returns the used LDAP Connection
		### ! Microsoft AD Servers do not allow password changing without LDAPS
		"""
		try:
			self.ldap_connection.extend.microsoft.modify_password(
				user=user_dn, 
				new_password=user_pwd
			)
		except Exception as e:
			self.ldap_connection.unbind()
			print(e)
			print(f'Could not update password for User DN: {user_dn}')
			data = {
				"ldap_response": self.ldap_connection.result
			}
			raise exc_user.UserUpdateError(data=data)
		return self.ldap_connection

	def ldap_user_exists(self, user_search: str, return_exception: bool = True):
		"""
		### Checks if LDAP User Exists on Directory
		Returns the used LDAP Connection
		"""
		# Send LDAP Query for user being created to see if it exists
		ldap_attributes = [
			LDAP_AUTH_USER_FIELDS["username"],
			'distinguishedName',
			'userPrincipalName',
		]
		self.get_user_object(
			user_search, 
			attributes=ldap_attributes
		)
		user = self.ldap_connection.entries

		# If user exists, return error
		if user != [] and return_exception:
			self.ldap_connection.unbind()
			exception = exc_ldap.LDAPObjectExists
			data = {
				"code": "user_exists",
				"user": user_search
			}
			exception.set_detail(exception, data)
			raise exception
		elif user != [] and not return_exception:
			return True
		return False

	def ldap_user_fetch(self, user_search):
		# Exclude Computer Accounts if settings allow it
		if EXCLUDE_COMPUTER_ACCOUNTS == True:
			self.ldap_filter_object = ldap_adsi.search_filter_add(self.ldap_filter_object, "!(objectclass=computer)")

		# Add filter for username
		self.ldap_filter_object = ldap_adsi.search_filter_add(self.ldap_filter_object, LDAP_AUTH_USER_FIELDS["username"] + "=" + user_search)
		
		user_obj = LDAPObject(**{
			"connection": self.ldap_connection,
			"ldapFilter": self.ldap_filter_object,
			"ldapAttributes": self.ldap_filter_attr
		})
		user_entry = user_obj.entry
		user_dict = user_obj.attributes

		if LDAP_LOG_READ == True:
			# Log this action to DB
			logToDB(
				user_id=self.request.user.id,
				actionType="READ",
				objectClass="USER",
				affectedObject=user_search
			)

		memberOfObjects = list()
		if 'memberOf' in user_dict:
			memberOf = user_dict.pop('memberOf')
			if isinstance(memberOf, list):
				for g in memberOf:
					memberOfObjects.append( self.get_group_attributes(g) )
			else:
				g = memberOf
				memberOfObjects.append( self.get_group_attributes(g) )

		### Also add default Users Group to be available as Selectable PID
		try:
			memberOfObjects.append( GroupViewMixin.getGroupByRID(user_dict['primaryGroupID']) )
		except:
			self.ldap_connection.unbind()
			raise

		if len(memberOfObjects) > 0:
			user_dict['memberOfObjects'] = memberOfObjects
		else:
			self.ldap_connection.unbind()
			raise exc_user.UserGroupsFetchError

		del memberOfObjects

		# Check if user is disabled
		user_dict['is_enabled'] = True
		try:
			if ldap_adsi.list_user_perms(user=user_entry, perm_search="LDAP_UF_ACCOUNT_DISABLE", user_is_object=False):
				user_dict['is_enabled'] = False
		except Exception as e:
			print(e)
			print(user_dict['distinguishedName'])

		# Check if user is disabled
		try:
			userPermissions = ldap_adsi.list_user_perms(user=user_entry, perm_search=None, user_is_object=False)
			user_dict['permission_list'] = userPermissions
		except Exception as e:
			print(e)
			print(user_dict['distinguishedName'])

		# Replace sAMAccountType Value with String Corresponding
		userAccountType = int(user_dict['sAMAccountType'])
		for accountType in LDAP_ACCOUNT_TYPES:
			accountTypeValue = LDAP_ACCOUNT_TYPES[accountType]
			if accountTypeValue == userAccountType:
				user_dict['sAMAccountType'] = accountType
		return user_dict

	def ldap_user_enable(self, user_object):
		user_to_enable = user_object['username']
		self.ldap_filter_object = ""

		# Exclude Computer Accounts if settings allow it
		if EXCLUDE_COMPUTER_ACCOUNTS == True:
			self.ldap_filter_object = ldap_adsi.search_filter_add(self.ldap_filter_object, "!(objectclass=computer)")

		# Add filter for username
		self.ldap_filter_object = ldap_adsi.search_filter_add(
			self.ldap_filter_object, 
			LDAP_AUTH_USER_FIELDS["username"] + "=" + user_to_enable
			)

		self.ldap_connection.search(
			LDAP_AUTH_SEARCH_BASE, 
			self.ldap_filter_object, 
			attributes=self.ldap_filter_attr
		)

		user = self.ldap_connection.entries
		dn = str(user[0].distinguishedName)
		permList = ldap_adsi.list_user_perms(user=user[0], user_is_object=False)
		
		try:
			newPermINT = ldap_adsi.calc_permissions(permList, perm_remove='LDAP_UF_ACCOUNT_DISABLE')
		except:
			print(traceback.format_exc())
			self.ldap_connection.unbind()
			raise exc_user.UserPermissionError

		self.ldap_connection.modify(dn,
			{'userAccountControl':[(MODIFY_REPLACE, [ newPermINT ])]}
		)

		if LDAP_LOG_UPDATE == True:
			# Log this action to DB
			logToDB(
				user_id=self.request.user.id,
				actionType="UPDATE",
				objectClass="USER",
				affectedObject=user_to_enable,
				extraMessage="ENABLE"
			)
		
		logger.debug(self.ldap_connection.result)
		return self.ldap_connection

	def ldap_user_disable(self, user_object):
		user_to_disable = user_object['username']
		self.ldap_filter_object = ""

		# Exclude Computer Accounts if settings allow it
		if EXCLUDE_COMPUTER_ACCOUNTS == True:
			self.ldap_filter_object = ldap_adsi.search_filter_add(self.ldap_filter_object, "!(objectclass=computer)")

		# Add filter for username
		self.ldap_filter_object = ldap_adsi.search_filter_add(
			self.ldap_filter_object, 
			LDAP_AUTH_USER_FIELDS["username"] + "=" + user_to_disable
			)

		self.ldap_connection.search(
			LDAP_AUTH_SEARCH_BASE, 
			self.ldap_filter_object, 
			attributes=self.ldap_filter_attr
		)

		user = self.ldap_connection.entries
		dn = str(user[0].distinguishedName)
		permList = ldap_adsi.list_user_perms(user=user[0], user_is_object=False)

		if dn == LDAP_AUTH_CONNECTION_USER_DN: raise exc_user.UserAntiLockout

		try:
			newPermINT = ldap_adsi.calc_permissions(permList, perm_add='LDAP_UF_ACCOUNT_DISABLE')
		except:
			print(traceback.format_exc())
			self.ldap_connection.unbind()
			raise exc_user.UserPermissionError

		self.ldap_connection.modify(dn,
			{'userAccountControl':[(MODIFY_REPLACE, [ newPermINT ])]}
		)

		if LDAP_LOG_UPDATE == True:
			# Log this action to DB
			logToDB(
				user_id=self.request.user.id,
				actionType="UPDATE",
				objectClass="USER",
				affectedObject=user_to_disable,
				extraMessage="DISABLE"
			)

		logger.debug("Located in: "+__name__+".disable")
		logger.debug(self.ldap_connection.result)
		return self.ldap_connection

	def ldap_user_unlock(self, user_object):
		user_name = user_object['username']
		# If data request for deletion has user DN
		if 'distinguishedName' in user_object.keys() and user_object['distinguishedName'] != "":
			logger.debug('Updating with distinguishedName obtained from front-end')
			logger.debug(user_object['distinguishedName'])
			user_dn = user_object['distinguishedName']
		# Else, search for username dn
		else:
			logger.debug('Updating with user dn search method')
			self.get_user_object(user_name)
			
			user = self.ldap_connection.entries
			user_dn = str(user[0].distinguishedName)
			logger.debug(user_dn)

		if not user_dn or user_dn == "":
			self.ldap_connection.unbind()
			raise exc_user.UserDoesNotExist

		self.ldap_connection.extend.microsoft.unlock_account(user_dn)
		if LDAP_LOG_UPDATE == True:
			# Log this action to DB
			logToDB(
				user_id=self.request.user.id,
				actionType="UPDATE",
				objectClass="USER",
				affectedObject=user_name,
				extraMessage="UNLOCK"
			)
		return self.ldap_connection
	
	def ldap_user_delete(self, user_object):
		if LDAP_AUTH_USER_FIELDS["username"] in user_object:
			user_name = user_object[LDAP_AUTH_USER_FIELDS["username"]]
		elif 'username' in user_object:
			user_name = user_object['username']
		else:
			raise exc_user.BaseException

		# If data request for deletion has user DN
		if 'distinguishedName' in user_object.keys() and user_object['distinguishedName'] != "":
			logger.debug('Deleting with distinguishedName obtained from front-end')
			logger.debug(user_object['distinguishedName'])
			user_dn = user_object['distinguishedName']
			if not user_dn or user_dn == "":
				self.ldap_connection.unbind()
				raise exc_user.UserDoesNotExist
			try:
				self.ldap_connection.delete(user_dn)
			except Exception as e:
				self.ldap_connection.unbind()
				print(e)
				data = {
					"ldap_response": self.ldap_connection.result
				}
				raise exc_ldap.BaseException(data=data)
		# Else, search for username dn
		else:
			logger.debug('Deleting with user dn search method')
			self.get_user_object(user_name)

			user_entry = self.ldap_connection.entries
			user_dn = str(user_entry[0].distinguishedName)
			logger.debug(user_dn)

			if not user_dn or user_dn == "":
				self.ldap_connection.unbind()
				raise exc_user.UserDoesNotExist
			try:
				self.ldap_connection.delete(user_dn)
			except Exception as e:
				self.ldap_connection.unbind()
				print(e)
				data = {
					"ldap_response": self.ldap_connection.result
				}
				raise exc_ldap.BaseException(data=data)

		if LDAP_LOG_DELETE == True:
			# Log this action to DB
			logToDB(
				user_id=self.request.user.id,
				actionType="DELETE",
				objectClass="USER",
				affectedObject=user_name
			)

		return self.ldap_connection
