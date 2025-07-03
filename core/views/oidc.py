################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.application
# Contains the ViewSet for SSO Application related operations

# ---------------------------------- IMPORTS --------------------------------- #
# Constants
from core.constants.oidc import (
	QK_NEXT,
	QK_ERROR,
	QK_ERROR_DETAIL,
	OIDC_ALLOWED_PROMPTS,
	OIDC_COOKIE_VUE_ABORT,
	OIDC_COOKIE_VUE_LOGIN,
	OIDC_COOKIE_VUE_REDIRECT,
	OIDC_COOKIE_CHOICES,
	OIDC_PROMPT_CONSENT,
)

# Mixins
from core.views.mixins.auth import CookieJWTAuthentication
from core.views.mixins.oidc import OidcAuthorizeMixin

# Views
from oidc_provider.views import AuthorizeView

# Models
from core.models.user import User
from oidc_provider.models import Client, UserConsent

# Http
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from urllib.parse import quote
from rest_framework.response import Response
from rest_framework import status
from urllib.parse import urlparse, parse_qs

# Exceptions
from django.core.exceptions import ObjectDoesNotExist

# ViewSets
from core.views.base import BaseViewSet

# Auth
from core.decorators.login import auth_required
from interlock_backend.settings import LOGIN_URL

# DB
from django.db import transaction

# Time
from django.utils import timezone
from datetime import datetime

# Others
from interlock_backend.encrypt import fernet_decrypt
from core.decorators.intercept import request_intercept
import logging
from interlock_backend.settings import (
	OIDC_INTERLOCK_LOGIN_COOKIE,
	OIDC_INTERLOCK_NEXT_COOKIE,
	OIDC_SKIP_CONSENT_EXPIRE,
)

################################################################################
logger = logging.getLogger(__name__)


def login_redirect_bad_request(error_detail: str | int = 400) -> HttpResponse:
	response = redirect(
		f"{LOGIN_URL}/?{QK_ERROR}=true&{QK_ERROR_DETAIL}={error_detail}"
	)
	response.delete_cookie(OIDC_INTERLOCK_LOGIN_COOKIE)
	response.delete_cookie(OIDC_INTERLOCK_NEXT_COOKIE)
	return response


class CustomOidcViewSet(BaseViewSet):
	@auth_required
	@request_intercept
	def reject(self, request: HttpRequest, pk=None):
		"""Endpoint for OIDC Consent Rejection."""
		user: User = request.user
		data: dict = request.data
		user_consent = None

		# Get client to delete consent after rejection.
		try:
			client = Client.objects.get(client_id=data["client_id"])
		except ObjectDoesNotExist:
			return login_redirect_bad_request("oidc_no_client")

		# Get Consent
		try:
			user_consent = UserConsent.objects.get(
				client_id=client.id, user_id=user.id
			)
			user_consent.delete()
		except ObjectDoesNotExist:
			pass
		except Exception as e:
			logger.exception(e)
			return login_redirect_bad_request("oidc_consent_get")

		response = Response(
			data={
				"code": 0,
				"code_msg": "ok",
			}
		)
		response.delete_cookie(OIDC_INTERLOCK_LOGIN_COOKIE)
		response.delete_cookie(OIDC_INTERLOCK_NEXT_COOKIE)
		return response

	@auth_required
	@request_intercept
	def consent(self, request: HttpRequest, pk=None):
		"""Endpoint for OIDC Consent."""
		user: User = request.user
		data: dict = request.data
		user_consent = None
		client = None
		if QK_NEXT not in data or not request.COOKIES.get(OIDC_INTERLOCK_NEXT_COOKIE, None):
			return login_redirect_bad_request("oidc_no_next_uri")
		try:
			client = Client.objects.get(client_id=data["client_id"])
		except ObjectDoesNotExist:
			return login_redirect_bad_request("oidc_no_client")
		try:
			user_consent = UserConsent.objects.get(
				client_id=client.id, user_id=user.id
			)
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
					expires_at=timezone.make_aware(datetime.now())
					+ OIDC_SKIP_CONSENT_EXPIRE,
					client_id=client.id,
					scope=client.scope,  # why the f do they save it like this?
				)
				user_consent.save()
			else:
				user_consent.expires_at = (
					timezone.make_aware(datetime.now())
					+ OIDC_SKIP_CONSENT_EXPIRE
				)
				user_consent.date_given = timezone.make_aware(datetime.now())
				user_consent.save()
		decrypted_next_uri = fernet_decrypt(request.COOKIES[OIDC_INTERLOCK_NEXT_COOKIE])
		return Response(
			data={
				"code": 0,
				"code_msg": "ok",
				"data": {"redirect_uri": decrypted_next_uri},
			}
		)


class OidcAuthorizeView(AuthorizeView, OidcAuthorizeMixin):
	@request_intercept
	def get(self, request: HttpRequest, *args, **kwargs):
		cookie_auth = CookieJWTAuthentication()
		self.authorize = self.authorize_endpoint_class(request)
		request.user, token = cookie_auth.authenticate(request)
		user: User = request.user
		login_url = None

		# Check if prompt param is valid based on our own custom implementation
		prompt = request.GET.get("prompt", None)
		if not prompt or (isinstance(prompt, str) and prompt.lower() == "none"):
			prompt = None
		elif prompt not in OIDC_ALLOWED_PROMPTS:
			return login_redirect_bad_request("oidc_prompt_unsupported")

		# Validate OIDC Parameters
		try:
			self.authorize.validate_params()
		except Exception as e:
			logger.exception(e)
			return login_redirect_bad_request(
				error_detail=status.HTTP_406_NOT_ACCEPTABLE
			)

		# If there's no OIDC Cookie, redirect to login with bad request code
		OIDC_COOKIE = request.COOKIES.get(
			OIDC_INTERLOCK_LOGIN_COOKIE, OIDC_COOKIE_VUE_REDIRECT
		).lower()
		if OIDC_COOKIE not in OIDC_COOKIE_CHOICES:
			return login_redirect_bad_request()

		# Retrieve required data
		self.get_relevant_objects(request=request)
		require_consent = (
			prompt == OIDC_PROMPT_CONSENT
			or self.user_requires_consent(user=user)
		)

		user_requires_auth = (
			user.is_anonymous
			or not user.is_authenticated
			or not user.is_enabled
			or require_consent
		)

		# Redirect to login if user requires auth
		if user_requires_auth:
			if OIDC_COOKIE == OIDC_COOKIE_VUE_ABORT:
				redirect_response = redirect(f"{LOGIN_URL}/?{QK_ERROR}=true")
				redirect_response.delete_cookie(OIDC_INTERLOCK_LOGIN_COOKIE)
				redirect_response.delete_cookie(OIDC_INTERLOCK_NEXT_COOKIE)
				return redirect_response
			elif OIDC_COOKIE in (
				OIDC_COOKIE_VUE_REDIRECT,
				OIDC_COOKIE_VUE_LOGIN,
			):
				return self.login_redirect()

		# Redirect to login with success or failure code
		else:
			# If user is not in ACL for requested resource, deny
			if not self.user_can_access_app(user=user):
				return login_redirect_bad_request(
					error_detail=status.HTTP_403_FORBIDDEN,
				)
			redirect_response: HttpResponse = redirect(
				self.authorize.create_response_uri()
			)

			# Remove redirection and next uri cookie
			redirect_response.delete_cookie(OIDC_INTERLOCK_LOGIN_COOKIE)
			redirect_response.delete_cookie(OIDC_INTERLOCK_NEXT_COOKIE)

			# Check if OIDC Library Response has any errors.
			if hasattr(redirect_response, "headers"):
				_redirect_url = None
				_parsed_url = None
				_parsed_query = None

				for location_key in ("Location", "location"):
					if location_key in redirect_response.headers:
						_redirect_url = redirect_response.headers[location_key]
						_parsed_url = urlparse(_redirect_url)
						_parsed_query = parse_qs(_parsed_url.query)

				# If there's an internal error attempt to passthrough code.
				if _parsed_query and QK_ERROR in _parsed_query:
					_error = quote(_parsed_query[QK_ERROR][0])
					logger.error(f"OIDC Error: {_error}")
					login_url = f"{LOGIN_URL}/?{QK_ERROR}=true&{QK_ERROR_DETAIL}={_error}"
					return self.abort_redirect(redirect(login_url))
			return redirect_response
