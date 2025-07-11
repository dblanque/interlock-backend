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
from core.config.runtime import RuntimeSettings

### Models
from core.models.user import User
from core.views.mixins.logs import LogMixin
from core.models.choices.log import (
	LOG_ACTION_UPDATE,
	LOG_CLASS_LDAP,
	LOG_ACTION_RENAME,
	LOG_ACTION_MOVE,
)

### Others
from rest_framework.exceptions import ValidationError
from rest_framework import status
from django.http.request import HttpRequest
from core.ldap.filter import LDAPFilter, LDAPFilterType
from ldap3 import Connection
from ldap3.utils.dn import safe_rdn, parse_dn
import logging
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


LDAP_DEFAULT_DIRTREE_FILTER = {
	"include": {
		"objectCategory": ["organizationalUnit", "top", "container"],
		"objectClass": [
			"builtinDomain",
			"user",
			"person",
			"group",
			"organizationalPerson",
			"computer",
		],
	}
}


class OrganizationalUnitMixin(viewsets.ViewSetMixin):
	ldap_connection: Connection
	request: HttpRequest
	VALID_FILTER_ITERABLES = (list, tuple, set)
	VALID_FILTER_NON_ITERABLES = (bool, str, int, float)
	VALID_FILTERS = (
		"exclude",
		"include",
		"iexact",
		"contains",
		"startswith",
		"endswith",
		"gte",
		"lte",
		"approx",
	)

	def validate_filter_dict(
		self, filter_dict: dict, allowed_keys: list | tuple = None
	):
		if not allowed_keys:
			allowed_keys = self.VALID_FILTERS
		for filter_type, conditions in filter_dict.items():
			if filter_type not in allowed_keys:
				raise ValidationError(
					f"Unknown LDAP Filter Type {filter_type}."
				)
			if not isinstance(conditions, dict):
				raise ValidationError(
					f"Filter Type value must be of type dict ({filter_type})."
				)

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
			_types = ", ".join(
				t.__name__ for t in self.VALID_FILTER_NON_ITERABLES
			)
			raise ValidationError(
				f"{attr} has an invalid type (must be any of {_types},"
				+ "can be multiple within a list, set or tuple)"
			)
		return False

	def process_ldap_filter_type(
		self, filter_type: str, conditions: dict
	) -> LDAPFilter:
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
		_exprs = (
			LDAPFilterType.AND,
			LDAPFilterType.OR,
		)
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
						filters = [
							LDAPFilter.not_(val_expr(attr, v)) for v in value
						]
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
					new_filter_is_expr = (
						new_filter.type in _exprs and new_filter.children
					)
					both_are_exprs = result_is_expr and new_filter_is_expr
					if (
						# A is expr, B is not
						(
							top_expr == multi_expr
							and result_is_expr
							and new_filter.type not in _exprs
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
					raise ValidationError(
						f"Filter value for '{filter_type}' cannot be an iterable."
					)
				op_map = {"gte": ">=", "lte": "<=", "approx": "~="}
				new_filter = LDAPFilter(
					type=LDAPFilterType(op_map[filter_type]),
					attribute=attr,
					value=value,
				)
				# Combine with existing filters using AND
				if result:
					result = LDAPFilter.and_(result, new_filter)
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
			type=LDAPFilterType.OR, children=None
		)
		if default_filter:
			self.validate_filter_dict(
				filter_dict=default_filter, allowed_keys=("include",)
			)

			# Build base filter from included attributes
			for attr, values in default_filter.get("include", {}).items():
				# Create OR filter for each attribute's allowed values
				# Explicit exclusion will skip default a include.
				for v in values:
					data_filter_exclude_values = data_filter_exclude.get(
						attr, []
					)
					if not data_filter_exclude or (
						data_filter_exclude
						and not v == data_filter_exclude_values
						and not v in data_filter_exclude_values
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
					result_filter = LDAPFilter.and_(result_filter, new_filter)
				else:
					result_filter = new_filter

		return result_filter

	def move_or_rename_object(
		self,
		distinguished_name: str,
		target_rdn: str = None,
		target_path: str = None,
		responsible_user: User = None,
	) -> str:
		"""Performs Move/Rename on LDAP Entry / Object with specified DN.

		Args:
			distinguished_name (str): LDAP Entry / Object Distinguished Name.
			target_rdn (str, optional): Will rename the object if changed from
				what is in distinguished_name. Defaults to None.
			target_path (str, optional): Will relocate object if changed from what
				is in distinguished_name. Defaults to None.

		* DN = Distinguished Name
		* RDN = Relative Distinguished Name

		Raises:
			exc_dirtree.DirtreeDistinguishedNameConflict: Raised when RDN
				identifier is invalid.
			exc_dirtree.DirtreeNewNameIsOld: Raised if new RDN is same as the
				old RDN.
			exc_dirtree.DirtreeDistinguishedNameConflict: Raised when both
				target_rdn and target_path are None.
			exc_dirtree.DirtreeMove: Raised when Move operation returned an
				error result on the LDAP Server.

		Returns:
			str: New Distinguished Name for LDAP Entry / Object
		"""
		if getattr(self, "connection", None) and not hasattr(
			self, "ldap_connection"
		):
			self.ldap_connection = self.connection

		try:
			parse_dn(dn=distinguished_name)
		except Exception as e:
			logger.exception(e)
			raise exc_ldap.DistinguishedNameValidationError

		if not target_rdn and not target_path:
			raise exc_dirtree.DirtreeDistinguishedNameConflict

		new_dn = None
		operation = LOG_ACTION_RENAME
		if target_path and target_rdn:
			operation = LOG_ACTION_UPDATE
		elif target_path:
			operation = LOG_ACTION_MOVE

		# If relative_dn is passed, namechange will be executed.
		if target_rdn:
			# Validations
			# Original Relative DN
			original_rdn: str = safe_rdn(dn=distinguished_name)[0]
			original_rdn_field = original_rdn.split("=")[0]
			if (
				original_rdn_field.lower()
				not in RuntimeSettings.LDAP_LDIF_IDENTIFIERS
			):
				raise exc_ldap.LDIFBadField(data={"field": "original_rdn"})

			# New Relative DN
			new_rdn = target_rdn
			new_rdn_field = target_rdn.split("=")
			# If field is in RDN, validate it
			if 1 < len(new_rdn_field) < 3:
				new_rdn_field = new_rdn_field[0]
				if (
					new_rdn_field.lower() != original_rdn_field.lower()
					or new_rdn_field.lower()
					not in RuntimeSettings.LDAP_LDIF_IDENTIFIERS
				):
					raise exc_ldap.LDIFBadField(data={"field": "new_rdn"})
			elif len(new_rdn_field) > 2:
				raise exc_ldap.DistinguishedNameValidationError
			else:
				new_rdn = f"{original_rdn_field}={new_rdn}"

			new_rdn = safe_rdn(dn=new_rdn)[0]
			if new_rdn == original_rdn:
				raise exc_dirtree.DirtreeNewNameIsOld
		else:
			new_rdn = safe_rdn(dn=distinguished_name)[0]

		try:
			if target_path:
				# Validate would-be new DN before operation
				new_dn = f"{new_rdn},{target_path}"
				self.ldap_connection.modify_dn(
					dn=distinguished_name,
					relative_dn=new_rdn,
					new_superior=target_path,
				)
			else:
				# Validate would-be new DN before operation
				old_path = distinguished_name.split(",")
				del old_path[0]
				old_path = ",".join(old_path)
				new_dn = f"{new_rdn},{old_path}"

				self.ldap_connection.modify_dn(
					dn=distinguished_name, relative_dn=new_rdn
				)
		except Exception as e:
			logger.exception(e)
			_code = None
			result_description: str = getattr(
				self.ldap_connection.result, "description", None
			)
			if result_description and isinstance(result_description, str):
				if result_description == "entryAlreadyExists":
					_code = 409
			raise exc_dirtree.DirtreeMove(
				data={
					"ldap_response": self.ldap_connection.result,
					"ldapObject": new_rdn,
					"code": status.HTTP_500_INTERNAL_SERVER_ERROR
					if not _code
					else _code,
				}
			)

		if not responsible_user:
			try:
				responsible_user = self.request.user
			except:
				responsible_user = User.objects.get(
					_distinguished_name=self.ldap_connection.user
				)

		DBLogMixin.log(
			user=responsible_user.id,
			operation_type=operation,
			log_target_class=LOG_CLASS_LDAP,
			log_target=f"{distinguished_name} to {new_dn}",
		)
		return new_dn
