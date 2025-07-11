################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.oidc
# Contains the Mixins for OIDC operations

# ---------------------------------- IMPORTS --------------------------------- #
# Constants
from core.constants.oidc import (
	QK_ERROR,
	QK_ERROR_DETAIL,
	OIDC_COOKIE_VUE_LOGIN,
	OIDC_ATTRS,
	OIDC_COOKIE_VUE_ABORT,
)
from interlock_backend.settings import (
	OIDC_INTERLOCK_LOGIN_COOKIE,
	OIDC_INTERLOCK_NEXT_COOKIE,
	OIDC_SKIP_CUSTOM_CONSENT,
	SIMPLE_JWT as JWT_SETTINGS,
)

# Http
from django.http import HttpResponse, HttpRequest
from django.shortcuts import redirect
from urllib.parse import quote

# Exception
from django.core.exceptions import ObjectDoesNotExist

# Models
from core.models.user import User, USER_TYPE_LOCAL, USER_TYPE_LDAP
from core.models.application import Application, ApplicationSecurityGroup
from oidc_provider.models import Client, UserConsent

# OIDC
from oidc_provider.lib.claims import ScopeClaims, STANDARD_CLAIMS

# Mixins
from core.views.mixins.ldap.user import LDAPUserMixin

# Time
from datetime import datetime, timedelta
from django.utils import timezone

# Others
from interlock_backend.encrypt import fernet_encrypt
from core.constants.attrs import LOCAL_ATTR_USER_GROUPS, LOCAL_ATTR_DN
import logging
from interlock_backend.settings import LOGIN_URL
from oidc_provider.lib.endpoints.authorize import AuthorizeEndpoint
from core.ldap.connector import LDAPConnector, recursive_member_search
from core.config.runtime import RuntimeSettings

################################################################################
logger = logging.getLogger()


def get_user_groups(user: User) -> list:
	"""Fetches User Application Security Groups or LDAP Groups,
	depending on type.

	Args:
		user (User): User Django Object

	Returns:
		list:  List of group DNs if LDAP User or List of
			local application group uuids.
	"""
	if user.user_type == USER_TYPE_LOCAL:
		_application_security_groups = user.asg_member.all()
		return [str(asg.uuid) for asg in _application_security_groups]
	elif user.user_type == USER_TYPE_LDAP:
		with LDAPConnector(force_admin=True) as ldc:
			groups = []
			user_mixin = LDAPUserMixin()
			user_mixin.search_attrs = [
				RuntimeSettings.LDAP_FIELD_MAP[LOCAL_ATTR_USER_GROUPS]
			]
			user_mixin.ldap_connection = ldc.connection
			ldap_user: dict = user_mixin.ldap_user_fetch(
				user_search=user.username,
				log_operation=False,
			)
			for group in ldap_user[LOCAL_ATTR_USER_GROUPS]:
				groups.append(group[LOCAL_ATTR_DN])
			return groups
	else:
		return []


class CustomScopeClaims(ScopeClaims, LDAPUserMixin):
	def setup(self):  # pragma: no cover
		# Define which claims are included for each scope
		self.claims = {
			"profile": {
				"sub": "Username",
				"username": "Username",
				"email": "Email",
				"groups": "Groups",
			},
			"email": {
				"email": "Email",
			},
			"groups": {
				"groups": "Groups",
			},
		}

	def create_response_dic(self):
		# Fetch user data based on the requested scopes
		response_dic = super().create_response_dic()
		self.user: User

		if "profile" in self.scopes:
			response_dic["username"] = self.user.username
			response_dic["email"] = self.user.email
			response_dic["groups"] = get_user_groups(self.user)

		if "email" in self.scopes:
			response_dic["email"] = self.user.email

		if "groups" in self.scopes:
			response_dic["groups"] = get_user_groups(self.user)

		return response_dic


def userinfo(claims: CustomScopeClaims, user: User):
	# Fetch user details from LDAP or your database
	for k in STANDARD_CLAIMS:
		if hasattr(user, k):
			claims[k] = getattr(user, k)
	claims["sub"] = user.username  # Subject identifier
	claims["preferred_username"] = user.username  # Subject identifier
	claims["username"] = user.username  # Subject identifier
	claims["groups"] = get_user_groups(user)
	return claims


class OidcAuthorizeEndpoint(AuthorizeEndpoint):
	def _extract_params(self) -> None:
		super()._extract_params()
		logger.debug("_extract_params():")
		logger.debug(self.params)
		return


class OidcAuthorizeMixin:
	authorize_endpoint_class = OidcAuthorizeEndpoint
	client_id: int | None
	client: Client | None
	application: Application | None
	request: HttpRequest | None

	def set_extra_params(self, data: dict, login_url: str) -> str:
		for key, value in data.items():
			if isinstance(value, bool):
				value = str(value).lower()
			elif isinstance(value, str):
				value = quote(value)
			else:
				value = quote(str(value))
			login_url = f"{login_url}&{key}={value}"
		return login_url

	def get_relevant_objects(self, request: HttpRequest):
		try:
			self.client_id = request.GET.get("client_id")
			self.application = Application.objects.get(client_id=self.client_id)
			self.client = Client.objects.get(client_id=self.client_id)
		except Exception as e:
			logger.exception(e)
			login_url = f"{LOGIN_URL}/?{QK_ERROR}=true&{QK_ERROR_DETAIL}=oidc_application_fetch"
			redirect_response = redirect(login_url)
			redirect_response.delete_cookie(OIDC_INTERLOCK_LOGIN_COOKIE)
			return redirect_response

	def user_requires_consent(self, user: User) -> bool:
		if OIDC_SKIP_CUSTOM_CONSENT:
			return False
		if not self.client.require_consent:
			return False

		consent = None
		try:
			consent = UserConsent.objects.get(
				user_id=user.id, client_id=self.client.id
			)
		except ObjectDoesNotExist:
			pass
		if consent:
			# Check if consent is re-usable or has expired
			if self.client.reuse_consent:
				if timezone.make_aware(datetime.now()) < consent.expires_at:
					return False

			# Don't require consent if it was given within the last minute.
			timedelta_consent_given = (
				timezone.make_aware(datetime.now()) - consent.date_given
			)
			if timedelta_consent_given < timedelta(minutes=1):
				return False
		return True

	def user_can_access_app(self, user: User):
		# If no Security Group exists for App, assume no filtering.
		try:
			application_group = ApplicationSecurityGroup.objects.get(
				application_id=self.application.id
			)
		except ObjectDoesNotExist:
			return True

		# If Application Security Group is disabled, assume no filtering.
		if not application_group.enabled:
			return True

		# Else check membership of corresponding group.
		if user.user_type == USER_TYPE_LDAP:
			with LDAPConnector(force_admin=True) as ldc:
				for distinguished_name in application_group.ldap_objects:
					if recursive_member_search(
						user_dn=user.distinguished_name,
						connection=ldc.connection,
						group_dn=distinguished_name,
					):
						return True
		elif user in application_group.users.all():
			return True
		return False

	def get_reject_url(self, redirect_uri: str) -> str:
		"""Returns only the base domain of the Redirection URL."""
		v = redirect_uri.lower()
		scheme, uri = v.split("://")
		uri = uri.split("/")[0]
		return f"{scheme}://{uri}"

	def get_login_url(self) -> str:
		self.authorize: OidcAuthorizeEndpoint
		original_url = self.request.get_full_path()
		# Encrypt the URL for temporary client-side storage
		encrypted_url = fernet_encrypt(original_url)
		login_url = f"{LOGIN_URL}/?"

		# These parameters need to be added because we're encrypting the
		# original redirection url for integrity and security purposes.
		# But the front-end needs some data.

		# Make rejection uri from base domain.
		# TODO - Change this to be a model setting for Applications.
		redirect_uri = self.client.redirect_uris[0]
		try:
			reject_uri = self.get_reject_url(redirect_uri)
		except:
			reject_uri = redirect_uri
		replace_params = {
			"next": str(True).lower(),
			"application": self.application.name,
			"client_id": self.client.client_id,
			"reuse_consent": self.client.reuse_consent,
			"require_consent": self.user_requires_consent(
				user=self.request.user
			),
			"redirect_uri": redirect_uri,
			"reject_uri": reject_uri,
		}

		# Set all non-replaced query params as well, they won't be used anyways
		# but the front-end might have some use for them.
		for attr in OIDC_ATTRS:
			if attr in replace_params:
				continue
			elif attr in self.authorize.params:
				val = self.authorize.params[attr]
				if isinstance(val, str):
					replace_params[attr] = self.authorize.params[attr]
				elif isinstance(val, (tuple, set, list)):
					replace_params[attr] = "+".join(self.authorize.params[attr])

		login_url = self.set_extra_params(
			data=replace_params, login_url=login_url
		)
		return login_url, encrypted_url

	def login_redirect(self) -> HttpResponse:
		login_url, encrypted_next = self.get_login_url()
		response = redirect(login_url)
		response.set_cookie(
			key=OIDC_INTERLOCK_LOGIN_COOKIE,
			value=OIDC_COOKIE_VUE_LOGIN,
			httponly=True,
			samesite=JWT_SETTINGS["AUTH_COOKIE_SAME_SITE"],
			secure=JWT_SETTINGS["AUTH_COOKIE_SECURE"],
			domain=JWT_SETTINGS["AUTH_COOKIE_DOMAIN"],
		)
		response.set_cookie(
			key=OIDC_INTERLOCK_NEXT_COOKIE,
			value=encrypted_next,
			httponly=True,
			samesite=JWT_SETTINGS["AUTH_COOKIE_SAME_SITE"],
			secure=JWT_SETTINGS["AUTH_COOKIE_SECURE"],
			domain=JWT_SETTINGS["AUTH_COOKIE_DOMAIN"],
		)
		return response

	def abort_redirect(self, response: HttpResponse) -> HttpResponse:
		response.set_cookie(
			key=OIDC_INTERLOCK_LOGIN_COOKIE,
			value=OIDC_COOKIE_VUE_ABORT,
			httponly=True,
			samesite=JWT_SETTINGS["AUTH_COOKIE_SAME_SITE"],
			secure=JWT_SETTINGS["AUTH_COOKIE_SECURE"],
			domain=JWT_SETTINGS["AUTH_COOKIE_DOMAIN"],
		)
		return response
