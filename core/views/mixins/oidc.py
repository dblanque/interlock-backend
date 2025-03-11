################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.oidc
# Contains the Mixins for OIDC operations

# ---------------------------------- IMPORTS -----------------------------------#
# Constants
from core.constants.oidc import (
	QK_NEXT,
	QK_ERROR,
	QK_ERROR_DETAIL,
	OIDC_COOKIE_VUE_LOGIN,
	OIDC_ATTRS,
	OIDC_COOKIE_VUE_ABORT
)
from interlock_backend.settings import (
	OIDC_INTERLOCK_LOGIN_COOKIE,
	OIDC_SKIP_CUSTOM_CONSENT,
	SIMPLE_JWT as JWT_SETTINGS
)

# Http
from django.http import HttpResponse, HttpRequest
from django.shortcuts import redirect
from urllib.parse import quote

# Exception
from django.core.exceptions import ObjectDoesNotExist

# Models
from core.models.user import (
	User,
	USER_TYPE_LOCAL,
	USER_TYPE_LDAP
)
from core.models.application import Application
from oidc_provider.models import Client, UserConsent

# OIDC
from oidc_provider.lib.claims import ScopeClaims, STANDARD_CLAIMS

# Mixins
from core.views.mixins.ldap.user import UserViewLDAPMixin

# Time
from datetime import datetime, timedelta
from django.utils import timezone

# Others
import logging
from interlock_backend.settings import LOGIN_URL
from oidc_provider.lib.endpoints.authorize import AuthorizeEndpoint
################################################################################
logger = logging.getLogger()

def get_user_groups(user: User) -> list:
    if user.user_type == USER_TYPE_LOCAL:
        return list(user.groups.values_list('name', flat=True))
    elif user.user_type == USER_TYPE_LDAP:
        # TODO
        # Fetch LDAP User Groups + Local Groups
        pass
    else:
        return []

class CustomScopeClaims(ScopeClaims, UserViewLDAPMixin):
    def setup(self):
        # Define which claims are included for each scope
        self.claims = {
            'profile': {
                'sub': 'Username',
                'username': 'Username',
                'email': 'Email',
                'groups': 'Groups',
            },
            'email': {
                'email': 'Email',
            },
            'groups': {
                'groups': 'Groups',
            },
        }

    def create_response_dic(self):
        # Fetch user data based on the requested scopes
        response_dic = super().create_response_dic()
        self.user: User

        if 'profile' in self.scopes:
            response_dic['username'] = self.user.username
            response_dic['email'] = self.user.email
            response_dic['groups'] = get_user_groups(self.user)

        if 'email' in self.scopes:
            response_dic['email'] = self.user.email

        if 'groups' in self.scopes:
            response_dic['groups'] = get_user_groups()

        return response_dic

def userinfo(claims: CustomScopeClaims, user: User):
    # Fetch user details from LDAP or your database
    for k in STANDARD_CLAIMS:
        if hasattr(user, k):
            claims[k] = getattr(user, k)
    claims['sub'] = user.username  # Subject identifier
    claims['preferred_username'] = user.username  # Subject identifier
    claims['username'] = user.username  # Subject identifier
    claims['groups'] = get_user_groups(user)
    return claims

class OidcAuthorizeEndpoint(AuthorizeEndpoint):
	def _extract_params(self) -> None:
		super()._extract_params()
		logger.debug("_extract_params():")
		logger.debug(self.params)
		return

class OidcAuthorizeMixin(object):
	authorize_endpoint_class = OidcAuthorizeEndpoint
	client_id: int
	client: Client
	application: Application
	request: HttpRequest
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

	def get_relevant_objects(self):
		try:
			self.client_id = self.request.GET.get("client_id")
			self.application = Application.objects.get(
				client_id=self.client_id)
			self.client = Client.objects.get(client_id=self.client_id)
		except Exception as e:
			logger.exception(e)
			login_url = f"{LOGIN_URL}/?{QK_ERROR}=true&{QK_ERROR_DETAIL}=oidc_application_fetch"
			redirect_response = redirect(login_url)
			redirect_response.delete_cookie(
				OIDC_INTERLOCK_LOGIN_COOKIE)
			return redirect_response

	def user_requires_consent(self, user: User) -> bool:
		if OIDC_SKIP_CUSTOM_CONSENT:
			return False
		if not self.client.require_consent:
			return False

		consent = None
		try:
			consent = UserConsent.objects.get(
				user_id=user.id, client_id=self.client.id)
		except ObjectDoesNotExist:
			pass
		if consent:
			if self.client.reuse_consent:
				if timezone.make_aware(datetime.now()) < consent.expires_at:
					return False
			timedelta_consent_given = (timezone.make_aware(datetime.now())-consent.date_given)
			if timedelta_consent_given < timedelta(minutes=1):
				return False
		return True

	def get_login_url(self) -> str:
		self.authorize: OidcAuthorizeEndpoint
		original_url = self.request.get_full_path()
		# Encode the URL for safe inclusion in another URL
		encoded_url = quote(original_url)
		login_url = f"{LOGIN_URL}/?{QK_NEXT}={encoded_url}"

		extra_params = {
			"application": self.application.name,
			"client_id": self.client.client_id,
			"reuse_consent": self.client.reuse_consent,
			"require_consent": self.user_requires_consent(user=self.request.user),
			"redirect_uri": self.client.redirect_uris[0]
		}
		for attr in OIDC_ATTRS:
			if attr in extra_params:
				continue
			if attr in self.authorize.params:
				extra_params[attr] = self.authorize.params[attr]
		login_url = self.set_extra_params(
			data=extra_params,
			login_url=login_url
		)
		return login_url

	def login_redirect(self) -> HttpResponse:
		login_url = self.get_login_url()
		response = redirect(login_url)
		response.set_cookie(
			key=OIDC_INTERLOCK_LOGIN_COOKIE,
			value=OIDC_COOKIE_VUE_LOGIN,
			httponly=True,
			samesite=JWT_SETTINGS['AUTH_COOKIE_SAME_SITE'],
			secure=JWT_SETTINGS['AUTH_COOKIE_SECURE'],
			domain=JWT_SETTINGS['AUTH_COOKIE_DOMAIN']
		)
		return response

	def abort_redirect(self, response: HttpResponse) -> HttpResponse:
		response.set_cookie(
			key=OIDC_INTERLOCK_LOGIN_COOKIE,
			value=OIDC_COOKIE_VUE_ABORT,
			httponly=True,
			samesite=JWT_SETTINGS['AUTH_COOKIE_SAME_SITE'],
			secure=JWT_SETTINGS['AUTH_COOKIE_SECURE'],
			domain=JWT_SETTINGS['AUTH_COOKIE_DOMAIN']
		)
		return response
