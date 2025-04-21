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
from rest_framework.exceptions import ValidationError
from deprecated import deprecated
from rest_framework import status
from django.http.request import HttpRequest
from core.ldap.filter import LDAPFilter, LDAPFilterType
from ldap3 import Connection
from ldap3.utils.dn import safe_dn, safe_rdn
import logging
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


LDAP_DEFAULT_DIRTREE_FILTER = {
	"include": {
		"objectCategory": [
			"organizationalUnit",
			"top",
			"container"
		],
		"objectClass": [
			"builtinDomain",
			"user",
			"person",
			"group",
			"organizationalPerson",
			"computer",
		]
	}
}

class OrganizationalUnitMixin(viewsets.ViewSetMixin):
	ldap_connection: Connection
	request: HttpRequest
	VALID_FILTER_ITERABLES = (list, tuple, set)
	VALID_FILTER_NON_ITERABLES = (bool, str, int, float)
	VALID_FILTERS = [
		"exclude",
		"include",
		"iexact",
		"contains",
		"startswith",
		"endswith",
		"gte",
		"lte",
		"approx",
	]

	def validate_filter_dict(self, filter_dict: dict, allowed_keys: list = None):
		if not allowed_keys:
			allowed_keys = self.VALID_FILTERS
		for filter_type, conditions in filter_dict.items():
			if filter_type not in allowed_keys:
				raise ValidationError(f"Unknown LDAP Filter Type {filter_type}.")
			if not isinstance(conditions, dict):
				raise ValidationError(f"Filter Type value must be of type dict ({filter_type}).")

	def cleanup_attr_value(self, value):
		"""Cleans up a filter dictionary value, returning the first if its a 
		1 element length iterable."""
		if not value:
			return None
		if isinstance(value, self.VALID_FILTER_ITERABLES):
			if len(value) == 1:
				if isinstance(value, set):
					return tuple(value)[0]
				return value[0]
		return value

	def is_multi_value_attribute(self, attr: str, value_or_values):
		"""Checks if a filter dictionary value is an iterable"""
		if isinstance(value_or_values, self.VALID_FILTER_ITERABLES):
			return True
		elif not isinstance(value_or_values, self.VALID_FILTER_NON_ITERABLES):
			_types = ', '.join(t.__name__ for t in self.VALID_FILTER_NON_ITERABLES)
			raise ValidationError(
				f"{attr} has an invalid type (must be any of {_types},"+
				"can be multiple within a list, set or tuple)"
			)
		return False
	
	def process_ldap_filter_type(self, filter_type: str, conditions: dict) -> LDAPFilter:
		"""Function that processes each LDAP Filter Dictionary Type and it's
		conditions.

		Args:
			filter_type (str): The filter type (include, iexact, etc.)
			conditions (dict): The conditions to apply, key-value pairs
				comprised of the LDAP Attribute key and it's value or values.

		Raises:
			ValidationError: Raised when an iterable is passed to a filter type
				that does not support it.

		Returns:
			LDAPFilter: LDAPFilter object with all conditions for type.
		"""
		result = None
		# Use AND expression by default.
		top_expr = LDAPFilter.and_
		multi_expr = LDAPFilter.and_
		val_expr = LDAPFilter.eq
		_exprs = (LDAPFilterType.AND, LDAPFilterType.OR,)
		if filter_type in ("include",):
			# Include/Exclude filters will evaluate all attrs with an OR expression.
			top_expr = LDAPFilter.or_
			multi_expr = LDAPFilter.or_
		if filter_type in ("contains", "startswith", "endswith"):
			# These filters will evaluate only values within
			# each attr with an OR expression.
			multi_expr = LDAPFilter.or_
			if filter_type in ("contains", "startswith", "endswith"):
				val_expr = LDAPFilter.substr

		if filter_type in (
			"exclude",
			"include",
			"iexact",
			"contains",
			"startswith",
			"endswith",
		):
			for attr, value in conditions.items():
				attr: str
				value = self.cleanup_attr_value(value)
				if not value:
					continue

				if self.is_multi_value_attribute(attr, value):
					if filter_type == "exclude":
						filters = [LDAPFilter.not_(val_expr(attr, v)) for v in value]
					else:
						filters = []
						for v in value:
							if filter_type == "contains":
								v = ["", v, ""]
							elif filter_type == "startswith":
								v = [v, ""]
							elif filter_type == "endswith":
								v = ["", v]
							filters.append(val_expr(attr, v))
					new_filter = multi_expr(*filters)
				else:
					if filter_type == "exclude":
						# Create filter for single attribute's value
						new_filter = LDAPFilter.not_(val_expr(attr, value))
					else:
						if filter_type == "contains":
							value = ["", value, ""]
						elif filter_type == "startswith":
							value = [value, ""]
						elif filter_type == "endswith":
							value = ["", value]
						# Create filter for single attribute's value
						new_filter = val_expr(attr, value)
		
				# Combine with existing filters using AND/OR depending on type
				# And expression matching.
				if result:
					result_is_expr = result.type in _exprs and result.children
					new_filter_is_expr = new_filter.type in _exprs and new_filter.children
					both_are_exprs = result_is_expr and new_filter_is_expr
					if (
						# A is expr, B is not
						(
							top_expr == multi_expr and 
	   						result_is_expr and
							new_filter.type not in _exprs
						)
						# Both are same expr
						or (both_are_exprs and result.type == new_filter.type)
					):
						result.children.append(new_filter)

					# A is not expr, B is expr
					elif result.type not in _exprs and new_filter_is_expr:
						new_filter.children.insert(0, result)
						result = new_filter

					# Different exprs
					else:
						result = top_expr(result, new_filter)
				else:
					result = new_filter
		else:
			for attr, value in conditions.items():
				if isinstance(value, self.VALID_FILTER_ITERABLES):
					raise ValidationError(f"Filter value for '{filter_type}' cannot be an iterable.")
				op_map = {
					"gte": ">=",
					"lte": "<=",
					"approx": "~="
				}
				new_filter = LDAPFilter(
					type=LDAPFilterType(op_map[filter_type]),
					attribute=attr,
					value=value
				)
				# Combine with existing filters using AND
				if result:
					result = LDAPFilter.and_(
						result,
						new_filter
					)
				else:
					result = new_filter
		return result

	def process_ldap_filter(
			self,
			data_filter: dict = None,
			default_filter: dict = None,
		) -> LDAPFilter:
		"""
		Process and merge LDAP filters from request data with default directory tree filters.

		Args:
			data: Request data filter dictionary containing user filters.
			default_filter: Custom filter definition (defaults to
				LDAP_DEFAULT_DIRTREE_FILTER) to apply along the request's
				data filter. Can be set to True/False or be a dict value.

		Returns:
			LDAPFilter: Combined resulting filter object ready for LDAP queries
		"""
		# Initialize resulting filter variable
		result_filter: str = None

		# Initialize filter dictionary with default values
		if default_filter is None or default_filter is True:
			default_filter = LDAP_DEFAULT_DIRTREE_FILTER.copy()
		elif default_filter:
			default_filter = default_filter.copy()

		if data_filter:
			self.validate_filter_dict(filter_dict=data_filter)

		data_filter_exclude: dict = data_filter.get("exclude", {})
		default_filter_include = LDAPFilter(
			type=LDAPFilterType.OR,
			children=None
		)
		if default_filter:
			self.validate_filter_dict(filter_dict=default_filter, allowed_keys=["include"])

			# Build base filter from included attributes
			for attr, values in default_filter.get("include", {}).items():
				# Create OR filter for each attribute's allowed values
				# Explicit exclusion will skip default a include.
				for v in values:
					data_filter_exclude_values = data_filter_exclude.get(attr, [])
					if not data_filter_exclude or (
						data_filter_exclude and
						not v == data_filter_exclude_values and
						not v in data_filter_exclude_values
					):
						default_filter_include.children.append(
							LDAPFilter.eq(attr, v)
						)

		# Combine default include filters
		if default_filter_include.children:
			result_filter = default_filter_include

		# Parse all other filters
		for filter_type, conditions in data_filter.items():
			conditions: dict
			new_filter = self.process_ldap_filter_type(filter_type, conditions)

			# Combine with existing filters using AND
			if new_filter:
				if result_filter:
					result_filter = LDAPFilter.and_(
						result_filter,
						new_filter
					)
				else:
					result_filter = new_filter

		return result_filter

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

	@deprecated
	def process_filter(self, data: dict = None, filter_dict: dict = None): # pragma: no cover
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
		if not isinstance(data, dict) and not data is None:
			raise TypeError("data must be of type dict or None.")

		ldap_filter: str = None
		filter_data: dict = {}
		if data:
			filter_data = data.get("filter", {})

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
