################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.ldap.domain
# Contains the ViewSet for Domain related operations

# ---------------------------------- IMPORTS --------------------------------- #
### Models
from core.views.mixins.logs import LogMixin
from core.models.interlock_settings import (
	InterlockSetting,
	INTERLOCK_SETTING_ENABLE_LDAP,
)
from core.models.user import User

### ViewSets
from core.views.base import BaseViewSet

### Exceptions
from django.core.exceptions import ObjectDoesNotExist
from core.exceptions import dns as exc_dns

### Mixins
from core.views.mixins.ldap.domain import DomainViewMixin

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.request import Request

### Others
from core.ldap import defaults
from core.config.runtime import RuntimeSettings
from core.models.validators.ldap import domain_validator
from core.decorators.login import auth_required, admin_required
from core.decorators.intercept import ldap_backend_intercept
from interlock_backend.settings import DEBUG as INTERLOCK_DEBUG
import logging
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


class LDAPDomainViewSet(BaseViewSet, DomainViewMixin):
	@auth_required
	def get_details(self, request: Request):
		_username_identifier = RuntimeSettings.LDAP_AUTH_USERNAME_IDENTIFIER
		data = {
			"realm": "",
			"name": "",
			"basedn": "",
			"user_selector": _username_identifier or "",
		}
		code = 0

		try:
			ldap_enabled = InterlockSetting.objects.get(
				name=INTERLOCK_SETTING_ENABLE_LDAP
			)
			ldap_enabled = ldap_enabled.value
		except ObjectDoesNotExist:
			ldap_enabled = False

		# Add realm, name and basedn only if it's not the default value
		_settings_for_frontend = (
			("realm", "LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN"),
			("name", "LDAP_DOMAIN"),
			("basedn", "LDAP_AUTH_SEARCH_BASE"),
		)
		if ldap_enabled:
			for response_key, setting_key in _settings_for_frontend:
				_runtime_value = getattr(RuntimeSettings, setting_key, None)
				_default_value = getattr(defaults, setting_key, None)
				if _runtime_value != _default_value:
					data[response_key] = _runtime_value

		if INTERLOCK_DEBUG:
			data["debug"] = INTERLOCK_DEBUG
		return Response(data={"code": code, "code_msg": "ok", "details": data})

	def validate_zones_filter(self, data: dict) -> str:
		"""Validate Zones Filter for zones fetching endpoint"""
		zone_filter = None

		# Set zone_filter
		request_filter: dict = data.get("filter", None)
		if request_filter or isinstance(request_filter, dict):
			if not "dnsZone" in request_filter:
				raise exc_dns.DNSZoneNotInRequest

			zone_filter: str = request_filter.get("dnsZone", None)
			if not isinstance(zone_filter, str):
				zone_filter = None

		if zone_filter:
			target_zone = zone_filter.replace(" ", "").strip()
			target_zone = target_zone.lower()
			if target_zone:
				try:
					domain_validator(target_zone)
				except Exception:
					raise exc_dns.DNSFieldValidatorFailed(
						data={"dnsZone": target_zone}
					)
		else:
			target_zone = RuntimeSettings.LDAP_DOMAIN
		return target_zone

	@auth_required
	@admin_required
	@ldap_backend_intercept
	@action(detail=False, methods=["post"])
	def get_zone(self, request: Request):
		user: User = request.user
		request_data: dict = request.data
		target_zone = self.validate_zones_filter(data=request_data)
		response_data = self.get_zone_records(
			user=user, target_zone=target_zone
		)

		return Response(
			data={"code": 0, "code_msg": "ok", "data": response_data}
		)

	@auth_required
	@admin_required
	@ldap_backend_intercept
	def create(self, request: Request):
		user: User = request.user
		request_data: dict = request.data

		target_zone: str = request_data.get("dnsZone", None)
		if not target_zone or not isinstance(target_zone, str):
			raise exc_dns.DNSZoneNotInRequest
		target_zone = target_zone.lower()

		try:
			domain_validator(target_zone)
		except:
			raise exc_dns.DNSFieldValidatorFailed(data={"dnsZone": target_zone})

		if (
			target_zone.lower() == RuntimeSettings.LDAP_DOMAIN.lower()
			or target_zone.lower() == "RootDNSServers".lower()
		):
			raise exc_dns.DNSZoneExists

		result = self.insert_zone(user=user, target_zone=target_zone)

		return Response(data={"code": 0, "code_msg": "ok", "result": result})

	@auth_required
	@admin_required
	@ldap_backend_intercept
	def destroy(self, request: Request):
		user: User = request.user
		request_data: dict = request.data
		result_zone = None
		result_forest = None

		target_zone: str = request_data.get("dnsZone", None)
		if not target_zone or not isinstance(target_zone, str):
			raise exc_dns.DNSZoneNotInRequest
		target_zone = target_zone.lower()

		try:
			domain_validator(target_zone)
		except:
			raise exc_dns.DNSFieldValidatorFailed(data={"dnsZone": target_zone})

		if (
			target_zone.lower() == RuntimeSettings.LDAP_DOMAIN.lower()
			or target_zone.lower() == "RootDNSServers".lower()
		):
			raise exc_dns.DNSZoneNotDeletable

		result_zone, result_forest = self.delete_zone(
			user=user, target_zone=target_zone
		)

		return Response(
			data={
				"code": 0,
				"code_msg": "ok",
				"result": {
					"dns": result_zone,
					"forest": result_forest,
				},
			}
		)
