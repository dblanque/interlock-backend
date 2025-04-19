################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.ldap.organizational_unit
# Contains the Mixin for Organizational Unit related operations

# --------------------------------- IMPORTS -----------------------------------#
### ViewSets
from rest_framework import viewsets

### Exceptions
from core.exceptions import dirtree as exc_dirtree, ldap as exc_ldap

### Interlock
from core.ldap.adsi import (
	join_ldap_filter,
	search_filter_from_dict,
	LDAP_FILTER_AND,
	LDAP_FILTER_OR,
)
from core.config.runtime import RuntimeSettings

### Models
from core.views.mixins.logs import LogMixin
from core.models.choices.log import (
	LOG_ACTION_UPDATE,
	LOG_CLASS_LDAP,
	LOG_ACTION_RENAME,
	LOG_ACTION_MOVE,
)

### Others
from django.http.request import HttpRequest
from rest_framework import status
from ldap3 import Connection
from ldap3.utils.dn import safe_dn, safe_rdn
import logging
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


class OrganizationalUnitMixin(viewsets.ViewSetMixin):
	ldap_connection: Connection
	request: HttpRequest

	# TODO - This should probably be reversed, each key should be a tuple
	# to fix non-uniqueness availability instead of reversing the k-v pairs.
	def process_filter(self, data: dict, filter_dict: dict = None):
		"""Process LDAP Directory Tree Request Filter

		Args:
			data (dict): Request data dictionary
			filter_dict (dict, optional): LDAP Filter dictionary to use when
			iexact is not used. Defaults to None.

		Raises:
			TypeError: When data is not of type dict.

		Returns:
			str: LDAP Filter String
		"""
		ldap_filter = ""

		if not isinstance(data, dict):
			raise TypeError("data must be of type dict.")
		filter_data: dict = data.get("filter", None)

		filter_data_iexact = filter_data.get("iexact", None)
		if filter_data_iexact and not isinstance(filter_data_iexact, dict):
			raise TypeError("filter_data_iexact must be of type dict.")

		filter_data_exclude = filter_data.get("exclude", None)
		if filter_data_exclude and not isinstance(filter_data_exclude, dict):
			raise TypeError("filter_data_exclude must be of type dict.")

		# Exact Filter
		if filter_data_iexact:
			logger.debug("Dirtree fetching with Filter iexact")
			for lookup_value, lookup_params in filter_data_iexact.items():
				# If lookup_params is a dict, fetch and use params.
				if isinstance(lookup_params, dict):
					lookup_type = lookup_params.pop("attr")
					lookup_exclude = False
					lookup_or = False

					if "exclude" in lookup_params:
						lookup_exclude = lookup_params.pop("exclude")
					if "or" in lookup_params:
						lookup_or = lookup_params.pop("or")

					if lookup_or:
						expr = LDAP_FILTER_OR
					else:
						expr = LDAP_FILTER_AND
					ldap_filter = join_ldap_filter(
						ldap_filter,
						f"{lookup_type}={lookup_value}",
						expression=expr,
						negate_add=lookup_exclude,
					)
				else:
					# If lookup_params isn't a dict, it's the type.
					lookup_type = lookup_params
					ldap_filter = join_ldap_filter(
						ldap_filter, f"{lookup_type}={lookup_value}")
		# Standard exclusion filter
		else:
			logger.debug("Dirtree fetching with Standard Exclusion Filter")
			if filter_dict is None:
				filter_dict = {
					**RuntimeSettings.LDAP_DIRTREE_CN_FILTER,
					**RuntimeSettings.LDAP_DIRTREE_OU_FILTER,
				}
			# Remove excluded field/value pairs from filter dict.
			if filter_data_exclude:
				for lookup_value in filter_data_exclude:
					if lookup_value in filter_dict:
						del filter_dict[lookup_value]

			ldap_filter = search_filter_from_dict(filter_dict)

			# Add excluded field/value pairs as negated filters to dict.
			if filter_data_exclude:
				for lookup_value in filter_data_exclude:
					lookup_type = filter_data_exclude[lookup_value]
					ldap_filter = join_ldap_filter(
						ldap_filter, f"{lookup_type}={lookup_value}", negate_add=True
					)

		logger.debug("LDAP Filter for Dirtree: %s", ldap_filter)
		return ldap_filter

	def move_or_rename_object(
		self, distinguished_name: str, relative_dn: str = None, ldap_path: str = None
	) -> str:
		"""Performs Move/Rename on LDAP Entry / Object with specified DN.

		Args:
			distinguished_name (str): LDAP Entry / Object Distinguished Name.
			relative_dn (str, optional): Will rename the object if changed from
				what is in distinguished_name. Defaults to None.
			ldap_path (str, optional): Will relocate object if changed from what
				is in distinguished_name. Defaults to None.

		* DN = Distinguished Name
		* RDN = Relative Distinguished Name		
		
		Raises:
			exc_dirtree.DirtreeDistinguishedNameConflict: Raised when RDN
				identifier is invalid.
			exc_dirtree.DirtreeNewNameIsOld: Raised if new RDN is same as the
				old RDN.
			exc_dirtree.DirtreeDistinguishedNameConflict: _description_
			exc_dirtree.DirtreeMove: _description_

		Returns:
			str: New Distinguished Name for LDAP Entry / Object
		"""
		try:
			distinguished_name = safe_dn(dn=distinguished_name)
		except Exception as e:
			logger.exception(e)
			raise exc_ldap.DistinguishedNameValidationError

		operation = LOG_ACTION_RENAME
		new_dn = None

		# If relative_dn is passed, namechange will be executed.
		if relative_dn:
			new_rdn = relative_dn
			original_rdn = safe_rdn(dn=distinguished_name)[0]
			original_rdn_field = original_rdn.split("=")[0]

			# Validations
			if original_rdn_field.lower() not in RuntimeSettings.LDAP_LDIF_IDENTIFIERS:
				raise exc_ldap.LDIFBadField

			if not new_rdn.startswith(original_rdn_field):
				new_rdn = f"{original_rdn_field}={new_rdn}"

			new_rdn = safe_rdn(dn=new_rdn)[0]
			if new_rdn == original_rdn:
				raise exc_dirtree.DirtreeNewNameIsOld
		else:
			new_rdn = safe_rdn(dn=distinguished_name)[0]

		if new_rdn == distinguished_name:
			raise exc_dirtree.DirtreeDistinguishedNameConflict

		if ldap_path:
			operation = LOG_ACTION_MOVE
		try:
			if ldap_path:
				self.ldap_connection.modify_dn(
					dn=distinguished_name,
					relative_dn=new_rdn,
					new_superior=ldap_path
				)
				new_dn = f"{new_rdn},{ldap_path}"
			else:
				self.ldap_connection.modify_dn(distinguished_name, new_rdn)
				new_path = distinguished_name.split(",")
				del new_path[0]
				new_path = ",".join(new_path)
				new_dn = f"{new_rdn},{new_path}"
		except Exception as e:
			logger.exception(e)
			_code = None
			result_description: str = getattr(
				self.ldap_connection.result, "description", None)
			if result_description and isinstance(result_description, str):
				if result_description == "entryAlreadyExists":
					_code = 409
			raise exc_dirtree.DirtreeMove(data={
				"ldap_response": self.ldap_connection.result,
				"ldapObject": new_rdn,
				"code": status.HTTP_500_INTERNAL_SERVER_ERROR if not _code \
						else _code
			})

		DBLogMixin.log(
			user=self.request.user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_LDAP,
			log_target=new_rdn,
			message=operation,
		)
		return new_dn
