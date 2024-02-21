################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.token
# Contributors: Martín Vilche
# Contains the ViewSet for Token Authentication related operations

#---------------------------------- IMPORTS -----------------------------------#
from django.utils.translation import gettext_lazy as _
from interlock_backend.settings import SIMPLE_JWT as JWT_SETTINGS
from django.contrib.auth.models import AnonymousUser
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from core.exceptions.base import AccessTokenInvalid, RefreshTokenExpired
################################################################################

EMPTY_TOKEN = ""
DATE_FMT_COOKIE = "%a, %d %b %Y %H:%M:%S GMT"

def RemoveTokenResponse(remove_refresh=False) -> Response:
	response = Response(status=status.HTTP_401_UNAUTHORIZED)
	response.set_cookie(
		key=JWT_SETTINGS['AUTH_COOKIE_NAME'],
		value='expired',
		httponly=True,
		samesite=JWT_SETTINGS['AUTH_COOKIE_SAME_SITE'],
		domain=JWT_SETTINGS['AUTH_COOKIE_DOMAIN']
	)
	if remove_refresh:
		response.set_cookie(
			key=JWT_SETTINGS['REFRESH_COOKIE_NAME'],
			value='expired',
			httponly=True,
			samesite=JWT_SETTINGS['AUTH_COOKIE_SAME_SITE'],
			domain=JWT_SETTINGS['AUTH_COOKIE_DOMAIN']
		)
	return response

class CookieJWTAuthentication(JWTAuthentication):  
	def authenticate(self, request):
		if(JWT_SETTINGS['AUTH_HEADER_NAME'] not in request.META): return AnonymousUser(), EMPTY_TOKEN
		if(len(request.META[JWT_SETTINGS['AUTH_HEADER_NAME']]) == 0): return AnonymousUser(), EMPTY_TOKEN
		tokens = {}
		split_cookies = request.META[JWT_SETTINGS['AUTH_HEADER_NAME']].split(';')
		for cookie in split_cookies:
			split_token = cookie.split('=')
			if(len(split_token)==0):
				return AnonymousUser(), EMPTY_TOKEN
			tokens[split_token[0].strip()] = split_token[1].strip()

		if (JWT_SETTINGS['AUTH_COOKIE_NAME'] not in tokens):
			return AnonymousUser(), EMPTY_TOKEN

		raw_token = tokens[JWT_SETTINGS['AUTH_COOKIE_NAME']]
		if raw_token is None or raw_token == 'expired':
			return AnonymousUser(), EMPTY_TOKEN
		try:
			validated_token = AccessToken(raw_token)
		except TokenError as e:
			raise AccessTokenInvalid()
		return self.get_user(validated_token), validated_token

	def refresh(self, request):
		if(JWT_SETTINGS['AUTH_HEADER_NAME'] not in request.META): raise RefreshTokenExpired()
		if(len(request.META[JWT_SETTINGS['AUTH_HEADER_NAME']]) == 0): raise RefreshTokenExpired()
		tokens = {}
		split_cookies = request.META[JWT_SETTINGS['AUTH_HEADER_NAME']].split(';')
		for cookie in split_cookies:
			split_token = cookie.split('=')
			if(len(split_token)==0):
				raise RefreshTokenExpired()
			tokens[split_token[0].strip()] = split_token[1].strip()

		if (JWT_SETTINGS['REFRESH_COOKIE_NAME'] not in tokens):
			raise RefreshTokenExpired()

		raw_token = tokens[JWT_SETTINGS['REFRESH_COOKIE_NAME']]
		if raw_token is None:
			raise RefreshTokenExpired()
		try:
			refreshed_tokens = RefreshToken(raw_token)
		except TokenError as e:
			raise RefreshTokenExpired()
		refreshed_tokens.set_jti()
		refreshed_tokens.set_exp()
		refreshed_tokens.set_iat()

		return refreshed_tokens.access_token, str(refreshed_tokens)