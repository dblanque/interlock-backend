################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.organizational_unit
# Contains the Mixin for Organizational Unit related operations

# ---------------------------------- IMPORTS -----------------------------------#
### ViewSets
from rest_framework import viewsets

### Exceptions
from core.exceptions import dirtree as exc_dirtree

### Interlock
from core.ldap.adsi import (
	search_filter_add,
	search_filter_from_dict,
	LDAP_FILTER_AND,
	LDAP_FILTER_OR,
)
from core.config.runtime import RuntimeSettings

### Models
from core.views.mixins.logs import LogMixin

### Others
import logging

# For future implementation
from ldap3.utils.dn import safe_rdn
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


class OrganizationalUnitMixin(viewsets.ViewSetMixin):
	def processFilter(self, data, filterDict=None):
		ldapFilter = ""

		if "filter" in data and "iexact" in data["filter"]:
			logger.debug("Dirtree fetching with Filter iexact")
			if len(data["filter"]["iexact"]) > 0:
				for f in data["filter"]["iexact"]:
					lookup_value = data["filter"]["iexact"][f]
					if isinstance(lookup_value, dict):
						lookup_type = lookup_value.pop("attr")
						if "exclude" in lookup_value:
							lookup_exclude = lookup_value.pop("exclude")
						else:
							lookup_exclude = False
						if "or" in lookup_value:
							lookup_or = lookup_value.pop("or")
						else:
							lookup_or = False

						if lookup_or:
							operator = LDAP_FILTER_OR
						else:
							operator = LDAP_FILTER_AND
						ldapFilter = search_filter_add(
							ldapFilter,
							f"{lookup_type}={f}",
							operator=operator,
							negate=lookup_exclude,
						)
					else:
						lookup_type = lookup_value
						ldapFilter = search_filter_add(ldapFilter, lookup_type + "=" + f)
		else:
			logger.debug("Dirtree fetching with Standard Exclusion Filter")
			if filterDict is None:
				filterDict = {
					**RuntimeSettings.LDAP_DIRTREE_CN_FILTER,
					**RuntimeSettings.LDAP_DIRTREE_OU_FILTER,
				}
			if "filter" in data and "exclude" in data["filter"]:
				if len(data["filter"]["exclude"]) > 0:
					for f in data["filter"]["exclude"]:
						lookup_type = data["filter"]["exclude"][f]
						if f in filterDict:
							del filterDict[f]

			ldapFilter = search_filter_from_dict(filterDict)

			# Where f is Filter Value, fType is the filter Type (not a Jaguar)
			# Example: objectClass=computer
			# f = computer
			# fType = objectClass
			if "filter" in data and "exclude" in data["filter"]:
				if len(data["filter"]["exclude"]) > 0:
					for f in data["filter"]["exclude"]:
						lookup_type = data["filter"]["exclude"][f]
						ldapFilter = search_filter_add(
							ldapFilter, f"{lookup_type}={f}", negate=True
						)

		logger.debug("LDAP Filter for Dirtree: ")
		logger.debug(ldapFilter)

		return ldapFilter

	def move_or_rename_object(
		self, distinguished_name: str, relative_dn: str = None, ldap_path: str = None
	) -> str:
		"""
		* relative_dn = Will rename the object if changed from what is in distinguished_name
		* ldap_path = Will relocate object if changed from what is in distinguished_name
		Returns new object Distinguished Name
		"""
		operation = "RENAME"
		new_dn = None

		# If relative_dn is passed, namechange will be executed.
		if relative_dn:
			new_relative_dn = relative_dn
			original_relative_dn = distinguished_name.split(",")[0]
			original_relative_dn_identifier = original_relative_dn.split("=")[0]

			# Validations
			if original_relative_dn_identifier.lower() not in RuntimeSettings.LDAP_LDIF_IDENTIFIERS:
				raise exc_dirtree.DirtreeDistinguishedNameConflict
			if not new_relative_dn.startswith(original_relative_dn_identifier):
				new_relative_dn = f"{original_relative_dn_identifier}={new_relative_dn}"
			if new_relative_dn == original_relative_dn:
				raise exc_dirtree.DirtreeNewNameIsOld
		else:
			new_relative_dn = distinguished_name.split(",")[0]

		if new_relative_dn == distinguished_name:
			raise exc_dirtree.DirtreeDistinguishedNameConflict

		if ldap_path:
			operation = "MOVE"
		try:
			if ldap_path:
				self.ldap_connection.modify_dn(
					distinguished_name, new_relative_dn, new_superior=ldap_path
				)
				new_dn = f"{new_relative_dn},{ldap_path}"
			else:
				self.ldap_connection.modify_dn(distinguished_name, new_relative_dn)
				new_path = distinguished_name.split(",")
				del new_path[0]
				new_path = ",".join(new_path)
				new_dn = f"{new_relative_dn},{new_path}"
		except Exception as e:
			print(e)
			data = {
				"ldap_response": self.ldap_connection.result,
				"ldapObject": new_relative_dn,
			}
			if hasattr(self.ldap_connection.result, "description"):
				if self.ldap_connection.result.description == "entryAlreadyExists":
					data["code"] = 409
			self.ldap_connection.unbind()
			raise exc_dirtree.DirtreeMove(data=data)

		if RuntimeSettings.LDAP_LOG_UPDATE == True:
			# Log this action to DB
			DBLogMixin.log(
				user_id=self.request.user.id,
				actionType="UPDATE",
				objectClass="LDAP",
				affectedObject=new_relative_dn,
				extraMessage=operation,
			)
		return new_dn
