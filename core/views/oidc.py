################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.application
# Contains the ViewSet for SSO Application related operations

# ---------------------------------- IMPORTS -----------------------------------#

# Mixins
from core.views.mixins.auth import CookieJWTAuthentication

# Views
from oidc_provider.views import AuthorizeView
from django.views.generic import View
from oidc_provider.lib.endpoints.authorize import AuthorizeEndpoint

# Models
from core.models.user import User
from core.models.application import Application
from oidc_provider.models import Client, UserConsent

# Django
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from urllib.parse import quote

# Exceptions
from django.core.exceptions import ObjectDoesNotExist
from oidc_provider.lib.errors import AuthorizeError

# ViewSets
from core.views.base import BaseViewSet

# Others
from rest_framework.response import Response
from rest_framework.decorators import action
from core.decorators.login import auth_required
from urllib.parse import urlparse, parse_qs
from interlock_backend.settings import (
	OIDC_INTERLOCK_LOGIN_COOKIE,
	OIDC_SKIP_CUSTOM_CONSENT,
	OIDC_SKIP_CONSENT_EXPIRE,
	SIMPLE_JWT as JWT_SETTINGS
)
from interlock_backend.settings import LOGIN_URL
import logging
import json
from django.utils import timezone
from django.db import transaction
from datetime import datetime, timedelta
################################################################################
logger = logging.getLogger(__name__)

QK_ERROR = "error"
QK_ERROR_DETAIL = "error_detail"
QK_NEXT = "next"
OIDC_ATTRS = (
	"client_id",
	"redirect_uri",
	"response_type",
	"scope",
	"nonce",
	"prompt",
	"code_challenge",
	"code_challenge_method",
)
OIDC_COOKIE_VUE_REDIRECT = "redirect"
OIDC_COOKIE_VUE_LOGIN = "login"
OIDC_COOKIE_VUE_ABORT = "abort"
OIDC_COOKIE_CHOICES = (
	OIDC_COOKIE_VUE_REDIRECT,
	OIDC_COOKIE_VUE_LOGIN,
	OIDC_COOKIE_VUE_ABORT,
)

class OidcAuthorizeEndpoint(AuthorizeEndpoint):
	def set_client_user_consent(self):
		"""
		Save the user consent given to a specific client.

		Return None.
		"""
		date_given = timezone.now()
		expires_at = date_given + OIDC_SKIP_CONSENT_EXPIRE

		uc, created = UserConsent.objects.get_or_create(
			user=self.request.user,
			client=self.client,
			defaults={
				"expires_at": expires_at,
				"date_given": date_given,
			},
		)
		uc.scope = self.params["scope"]
		# Rewrite expires_at and date_given if object already exists.
		if not created:
			uc.expires_at = expires_at
			uc.date_given = date_given
		uc.save()

	def _extract_params(self) -> None:
		super()._extract_params()
		logger.debug("_extract_params():")
		logger.debug(self.params)
		return

def login_redirect_bad_request(error_detail: str | int = 400) -> HttpResponse:
	response = redirect(
		f"{LOGIN_URL}/?{QK_ERROR}=true&{QK_ERROR_DETAIL}={error_detail}")
	response.delete_cookie(OIDC_INTERLOCK_LOGIN_COOKIE)
	return response

class CustomOidcViewSet(BaseViewSet):

	@action(detail=False, methods=['post'])
	@auth_required(require_admin=False)
	def consent(self, request, pk=None):
		user: User = request.user
		data: dict = request.data
		user_consent = None
		client = None
		if not "next" in data:
			return login_redirect_bad_request("oidc_no_next_uri")
		try:
			client = Client.objects.get(client_id=data["client_id"])
		except:
			return login_redirect_bad_request("oidc_no_client")
		try:
			user_consent = UserConsent.objects.get(
				client_id=client.id, user_id=user.id)
		except ObjectDoesNotExist:
			pass
		except Exception as e:
			logger.exception(e)
			return login_redirect_bad_request("oidc_consent_get")

		with transaction.atomic():
			if not user_consent:
				user_consent = UserConsent.objects.create(
					user=user,
					date_given=timezone.make_aware(datetime.now()),
					expires_at=timezone.make_aware(datetime.now()) + OIDC_SKIP_CONSENT_EXPIRE,
					client_id=client.id,
					scope=client.scope # why the f do they save it like this?
				)
				user_consent.save()
			else:
				user_consent.expires_at = timezone.make_aware(datetime.now()) + OIDC_SKIP_CONSENT_EXPIRE
				user_consent.date_given = timezone.make_aware(datetime.now())
				user_consent.save()
		return Response(
			data={
				"code": 0,
				"code_msg": "ok",
				"data": {"redirect_uri": data["next"]}
			}
		)


class OidcAuthorizeView(AuthorizeView):
	authorize_endpoint_class = OidcAuthorizeEndpoint
	client_id: int
	client: Client
	application: Application

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

	def get(self, request: HttpRequest, *args, **kwargs):
		cookie_auth = CookieJWTAuthentication()
		self.authorize = self.authorize_endpoint_class(request)
		request.user, token = cookie_auth.authenticate(request)
		user: User = request.user
		login_url = None

		# VALIDATION
		try:
			self.authorize.validate_params()
		except:
			login_redirect_bad_request()

		OIDC_COOKIE = request.COOKIES.get(
			OIDC_INTERLOCK_LOGIN_COOKIE, OIDC_COOKIE_VUE_REDIRECT).lower()
		if OIDC_COOKIE not in OIDC_COOKIE_CHOICES:
			login_redirect_bad_request()

		# FETCH DATA
		self.get_relevant_objects()
		require_consent = self.user_requires_consent(user=user)

		# TODO - Check if user is in application's groups (LDAP, Local, etc.)
		# Redirect to login
		if (
			user.is_anonymous or
			not user.is_authenticated or
			not user.is_enabled or
			require_consent
		):
			if OIDC_COOKIE == OIDC_COOKIE_VUE_ABORT:
				redirect_response = redirect(f"{LOGIN_URL}/?{QK_ERROR}=true")
				redirect_response.delete_cookie(OIDC_INTERLOCK_LOGIN_COOKIE)
				return redirect_response
			elif OIDC_COOKIE in (OIDC_COOKIE_VUE_REDIRECT, OIDC_COOKIE_VUE_LOGIN):
				return self.login_redirect()
		# Redirect to login with failure code
		else:
			redirect_response: HttpResponse = redirect(self.authorize.create_response_uri())
			redirect_response.delete_cookie(OIDC_INTERLOCK_LOGIN_COOKIE)
			if hasattr(redirect_response, "headers"):
				_redirect_url = None
				_parsed_url = None
				_parsed_query = None
				for location_key in ("Location", "location"):
					if location_key in redirect_response.headers:
						_redirect_url = redirect_response.headers[location_key]
						_parsed_url = urlparse(_redirect_url)
						_parsed_query = parse_qs(_parsed_url.query)
				if _parsed_query and "error" in _parsed_query:
					_error = quote(_parsed_query["error"][0])
					logger.error(f"OIDC Error: {_error}")
					login_url = f"{LOGIN_URL}/?{QK_ERROR}=true&{QK_ERROR_DETAIL}={_error}"
					return self.abort_redirect(redirect(login_url))
			return redirect_response


# class CustomTokenView(TokenView):
# 	def post(self, request, *args, **kwargs):
# 		# Add custom token issuance logic (e.g., track token grants)
# 		response = super().post(request, *args, **kwargs)
# 		if 'access_token' in response.data:
# 			track_access_token(request.user, response.data['access_token'])
# 		return response
