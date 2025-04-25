from core.models.ldap_settings_runtime import RuntimeSettingsSingleton


class GroupViewsetFilterAttributeBuilder:
	def __init__(self, settings: RuntimeSettingsSingleton):
		self.RunningSettings = settings

	def get_list_filter(self):
		return ["cn", "distinguishedName", "groupType", "member"]

	def get_fetch_filter(self):
		return [
			"cn",
			"mail",
			"member",
			"distinguishedName",
			"groupType",
			"objectSid",
		]

	def get_insert_filter(self):
		return [
			"cn",
			"distinguishedName",
			"userPrincipalName",
		]
