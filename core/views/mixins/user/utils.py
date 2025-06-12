################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.user.utils
# Contains the Mixin for User Utilities

# ---------------------------------- IMPORTS --------------------------------- #
### Exceptions
from core.exceptions import base as exc_base, users as exc_user

### Models
from core.models.interlock_settings import (
	InterlockSetting,
	INTERLOCK_SETTING_ENABLE_LDAP,
)

### Exceptions
from django.core.exceptions import ObjectDoesNotExist

### Constants
from core.constants.attrs import local as local_attrs

### Other
import logging
from core.views.mixins.logs import LogMixin
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)

ALL_LOCAL_ATTRS = {
	k: getattr(local_attrs, k)
	for k in dir(local_attrs)
	if k.startswith("LOCAL_")
}


class UserUtilsMixin:
	ldap_backend_enabled = False

	def get_ldap_backend_enabled(self):
		"""Gets current LDAP Backend Enabled Setting"""
		try:
			self.ldap_backend_enabled = InterlockSetting.objects.get(
				name=INTERLOCK_SETTING_ENABLE_LDAP
			).value
		except ObjectDoesNotExist:
			self.ldap_backend_enabled = False

	def validate_local_attrs(self, l: list, check_attrs: list[str] = None):
		"""Validates list of keys against local system attributes

		Raises:
			exc_base.BadRequest: When validation fails.
		"""
		if not check_attrs:
			check_attrs = ALL_LOCAL_ATTRS.values()

		for v in l:
			if v not in check_attrs or not isinstance(v, str):
				raise exc_base.BadRequest(
					data={
						"detail": "All headers and/or header mappings must"
						"be of type str and existing local attributes "
						"(Offending key: %s)." % (str(v))
					}
				)

	def validate_csv_headers(
		self,
		headers: list[str],
		csv_map: dict[str] = None,
		check_attrs: list[str] = None,
	):
		if not headers or not isinstance(headers, list):
			raise exc_user.UserBulkInsertMappingError(
				data={"detail": f"Key 'headers' must be of type list."}
			)
		if csv_map and not isinstance(csv_map, dict):
			raise exc_user.UserBulkInsertMappingError(
				data={"detail": f"Key 'csv_map' must be of type dict"}
			)

		if csv_map:
			csv_map_keys = list(csv_map.keys())
			# Compare length with headers
			if len(csv_map_keys) != len(headers):
				raise exc_user.UserBulkInsertMappingError(
					data={
						"detail": "Header mapping length mismatch with CSV headers."
					}
				)

			# Ensure local username key exists
			if not local_attrs.LOCAL_ATTR_USERNAME in csv_map_keys:
				raise exc_user.UserBulkInsertMappingError(
					data={
						"detail": "{h} header is required in mapping".format(
							h=local_attrs.LOCAL_ATTR_USERNAME
						)
					}
				)

			# Validate csv_map keys with local attributes
			self.validate_local_attrs(csv_map_keys, check_attrs)

			# Check that all mapping values effectively are in headers
			for v in csv_map.values():
				if v not in headers:
					raise exc_user.UserBulkInsertMappingError(
						data={"detail": "Unmapped key detected (%s)" % (v)}
					)
		else:
			if not local_attrs.LOCAL_ATTR_USERNAME in headers:
				raise exc_user.UserBulkInsertMappingError(
					data={
						"detail": "{h} header is required in mapping".format(
							h=local_attrs.LOCAL_ATTR_USERNAME
						)
					}
				)

			self.validate_local_attrs(headers, check_attrs)

	def validate_and_map_csv_headers(
		self,
		headers: list[str],
		csv_map: dict[str] = None,
		check_attrs: list[str] = None,
	):
		"""Validate and map csv headers to local attributes.

		Args:
			headers (list[str]): List of csv headers
			csv_map (dict[str]): Dictionary mapping of local attributes to csv
				headers.
			check_attrs (list[str]): List of attributes to check against,
				defaults to check all LOCAL_ATTR prefixed constants in system.

		Returns:
			dict: Mapped attribute keys { index: local_attr }
		"""
		index_map = {}

		# Validate
		self.validate_csv_headers(
			headers=headers,
			csv_map=csv_map,
			check_attrs=check_attrs,
		)

		# Map Header Column Indexes
		if csv_map:
			for local_alias, csv_alias in csv_map.items():
				index_map[headers.index(csv_alias)] = local_alias
		else:
			index_map = {
				idx: local_alias for idx, local_alias in enumerate(headers)
			}

		return index_map

	def cleanup_empty_str_values(self, d: dict) -> dict:
		_new_d = d.copy()
		delete_keys = []
		for k, v in d.items():
			if isinstance(v, str) and not v:
				delete_keys.append(k)
		for k in delete_keys:
			del _new_d[k]
		return _new_d
