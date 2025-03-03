
from core.models.ldap_settings_runtime import RunningSettingsClass

class UserViewsetFilterBuilder():
	def __init__(self, settings: RunningSettingsClass):
		self.RunningSettings = settings

	def get_list_filter(self):
		return [
			"givenName",
			"sn",
			"displayName",
			self.RunningSettings.LDAP_AUTH_USER_FIELDS["username"],
			"mail",
			"distinguishedName",
			"userAccountControl"
		]
	
	def get_fetch_filter(self):
		return [
			'givenName', 
			'sn', 
			'displayName', 
			self.RunningSettings.LDAP_AUTH_USER_FIELDS["username"], 
			'mail',
			'telephoneNumber',
			'streetAddress',
			'postalCode',
			'l', # Local / City
			'st', # State/Province
			'countryCode', # INT
			'co', # 2 Letter Code for Country
			'c', # Full Country Name
			'wWWHomePage',
			'distinguishedName',
			'userPrincipalName',
			'userAccountControl', # Permission ACLs
			'whenCreated',
			'whenChanged',
			'lastLogon',
			'badPwdCount',
			'pwdLastSet',
			'primaryGroupID',
			'objectClass',
			'objectCategory',
			'objectSid',
			'sAMAccountType',
			'memberOf',
		]

	def get_update_filter(self):
		return [
			self.RunningSettings.LDAP_AUTH_USER_FIELDS["username"],
			'distinguishedName',
			'userPrincipalName',
			'userAccountControl',
		]

	def get_bulk_insert_filter(self):
		return [
			self.RunningSettings.LDAP_AUTH_USER_FIELDS["username"],
			'distinguishedName',
			'userPrincipalName',
		]

	def get_update_exclude_keys(self):
		return [
			# Added keys for front-end normalization
			'name',
			'type',

			# Samba keys to intentionally exclude
			'password', 
			'passwordConfirm',
			'path',
			'permission_list', # This array is parsed and calculated later
			'distinguishedName', # We don't want the front-end generated DN
			'username', # LDAP Uses sAMAccountName
			'whenChanged',
			'whenCreated',
			'lastLogon',
			'badPwdCount',
			'pwdLastSet',
			'is_enabled',
			'sAMAccountType',
			'objectCategory',
			'objectSid',
			'objectRid'
		]
	
	def get_update_self_exclude_keys(self):
		return [
			'can_change_pwd',
			'password', 
			'passwordConfirm',
			'path',
			'permission_list', # This array is parsed and calculated later
			'distinguishedName', # We don't want the front-end generated DN
			'username', # LDAP Uses sAMAccountName
			'whenChanged',
			'whenCreated',
			'lastLogon',
			'badPwdCount',
			'pwdLastSet',
			'is_enabled',
			'sAMAccountType',
			'objectCategory',
			'userAccountControl',
			'objectClass',
			'primaryGroupID'
		]

	def get_fetch_me_filter(self):
		_REMOVE = [
			"primaryGroupID",
			"objectClass",
			"objectCategory",
			"objectSid",
			"sAMAccountType",
			"memberOf"
		]
		_RESULT = self.get_fetch_filter()
		for value in _REMOVE:
			_RESULT.remove(value)
		return _RESULT