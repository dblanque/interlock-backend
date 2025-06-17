################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.constants.search_attr_builder
# Contains the search attribute builder base class for LDAP Queries.

#---------------------------------- IMPORTS -----------------------------------#
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
################################################################################


class SearchAttrBuilder:
	def _to_ldap(self, k: str) -> str:
		"""Convert Local Attribute Key to LDAP Attribute Key
		Args:
			k (str): Local Attribute Constant Key (LOCAL_ATTR_*)

		Returns:
			str: Corresponding LDAP mapped field for Local Attribute Key
		"""
		try:
			return self.RuntimeSettings.LDAP_FIELD_MAP[k]
		except:
			raise Exception(f"Could not find mapped field {k}.")

	def __init__(self, settings: RuntimeSettingsSingleton):
		if not isinstance(settings, RuntimeSettingsSingleton):
			raise TypeError(
				"Initialization for cls requires RuntimeSettingsSingleton instance."
			)
		self.RuntimeSettings = settings
