########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType

################################################################################
from core.models.user import User
from tests.test_core.test_views.conftest import APIClientFactory
from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework import status
from django.http.cookie import SimpleCookie
from rest_framework_simplejwt.exceptions import TokenError
from interlock_backend.test_settings import SIMPLE_JWT as JWT_SETTINGS
from core.views.mixins.auth import DATE_FMT_COOKIE
from rest_framework_simplejwt.tokens import RefreshToken
from django.urls import reverse
from datetime import timedelta, datetime
import time


class TestRefresh:
	endpoint = reverse("token-refresh")

	def test_get_refresh_access_valid(
		self,
		normal_user_client: APIClient,
	):
		start_time = time.time()

		response: Response = normal_user_client.post(self.endpoint)

		# Check response status
		assert response.status_code == 200

		# Check response data contains expiry timestamps
		assert "access_expire" in response.data
		assert "refresh_expire" in response.data

		# Verify timestamps are in the future
		assert response.data["access_expire"] > start_time * 1000
		assert response.data["refresh_expire"] > start_time * 1000

		# Check cookies are set
		assert JWT_SETTINGS["AUTH_COOKIE_NAME"] in response.cookies
		assert JWT_SETTINGS["REFRESH_COOKIE_NAME"] in response.cookies

		# Verify cookie attributes
		access_cookie: SimpleCookie = response.cookies[
			JWT_SETTINGS["AUTH_COOKIE_NAME"]
		]
		if JWT_SETTINGS["AUTH_COOKIE_HTTP_ONLY"]:
			assert "httponly" in access_cookie._flags
		else:
			assert "httponly" not in access_cookie._flags
		if JWT_SETTINGS["AUTH_COOKIE_SECURE"]:
			assert "secure" in access_cookie._flags
		else:
			assert "secure" not in access_cookie._flags
		assert (
			access_cookie["samesite"] == JWT_SETTINGS["AUTH_COOKIE_SAME_SITE"]
		)

	def test_expired_refresh_token(
		self,
		f_api_client: APIClientFactory,
		normal_user: User,
	):
		# Create an expired refresh token manually
		refresh = RefreshToken.for_user(normal_user)
		refresh.set_exp(lifetime=timedelta(seconds=-1))  # Set to expired
		normal_user_client = f_api_client(
			user=normal_user,
			use_endpoint=False,
			refresh_token=refresh,
		)

		# Set the expired token in cookies
		normal_user_client.cookies[JWT_SETTINGS["REFRESH_COOKIE_NAME"]] = str(
			refresh
		)

		response: Response = normal_user_client.post(self.endpoint)

		assert response.status_code == 401
		assert (
			"refresh_token" not in response.cookies
		)  # No new refresh token issued

	def test_refresh_token_rotation(self, normal_user_client: APIClient):
		# Get original refresh token
		original_refresh = normal_user_client.cookies[
			JWT_SETTINGS["REFRESH_COOKIE_NAME"]
		].value

		# First refresh
		response1: Response = normal_user_client.post(self.endpoint)
		new_refresh1 = response1.cookies[
			JWT_SETTINGS["REFRESH_COOKIE_NAME"]
		].value

		# Second refresh with the new token
		normal_user_client.cookies[JWT_SETTINGS["REFRESH_COOKIE_NAME"]] = (
			new_refresh1
		)
		response2: Response = normal_user_client.post(self.endpoint)
		new_refresh2 = response2.cookies[
			JWT_SETTINGS["REFRESH_COOKIE_NAME"]
		].value

		# Verify all tokens are different (rotation is working)
		assert original_refresh != new_refresh1
		assert new_refresh1 != new_refresh2

	def test_refresh_token_expiry_times(
		self,
		normal_user_client: APIClient,
	):
		response: Response = normal_user_client.post(self.endpoint)

		# Get current time and expected expiry durations
		current_time = datetime.now()
		access_expire_time = datetime.fromtimestamp(
			response.data["access_expire"] / 1000
		)
		refresh_expire_time = datetime.fromtimestamp(
			response.data["refresh_expire"] / 1000
		)

		# Calculate expected durations based on SIMPLE_JWT
		expected_access_duration = JWT_SETTINGS["ACCESS_TOKEN_LIFETIME"]
		expected_refresh_duration = JWT_SETTINGS["REFRESH_TOKEN_LIFETIME"]

		# Check if calculated durations are approximately correct, 5 sec leeway
		assert abs(
			(access_expire_time - current_time) - expected_access_duration
		) < timedelta(seconds=5)
		assert abs(
			(refresh_expire_time - current_time) - expected_refresh_duration
		) < timedelta(seconds=5)

	def test_cookie_expiry_format(self, normal_user_client: APIClient):
		response: Response = normal_user_client.post(self.endpoint)

		access_cookie = response.cookies[JWT_SETTINGS["AUTH_COOKIE_NAME"]]
		refresh_cookie = response.cookies[JWT_SETTINGS["REFRESH_COOKIE_NAME"]]

		# Verify expiry format matches DATE_FMT_COOKIE
		try:
			datetime.strptime(access_cookie["expires"], DATE_FMT_COOKIE)
			datetime.strptime(refresh_cookie["expires"], DATE_FMT_COOKIE)
		except ValueError:
			pytest.fail("Cookie expiry format is incorrect")


class TestLogout:
	endpoint = reverse("token-revoke")

	@pytest.mark.parametrize(
		"user_fixture_type",
		(
			"normal",
			"admin",
		),
	)
	def test_logout_success(
		self,
		user_fixture_type: str,
		request: FixtureRequest,
	):
		user: User = request.getfixturevalue(f"{user_fixture_type}_user")
		api_client: APIClient = request.getfixturevalue(
			f"{user_fixture_type}_user_client"
		)
		logout_response: Response = api_client.post(self.endpoint)
		assert logout_response.status_code == status.HTTP_200_OK

		post_logout_response: Response = api_client.post(self.endpoint)
		assert post_logout_response.status_code == status.HTTP_401_UNAUTHORIZED

	@pytest.mark.parametrize(
		"exception_type, expected_code",
		(
			(TokenError, status.HTTP_400_BAD_REQUEST),
			(Exception, status.HTTP_500_INTERNAL_SERVER_ERROR),
		),
	)
	def test_logout_token_error(
		self,
		exception_type,
		expected_code: int,
		normal_user_client: APIClient,
		mocker: MockerFixture,
	):
		mocker.patch("core.views.auth.RefreshToken", side_effect=exception_type)
		response: Response = normal_user_client.post(self.endpoint)
		assert response.status_code == expected_code

	def test_logout_no_token(
		self,
	):
		unauth_api_client = APIClient()
		response: Response = unauth_api_client.post(self.endpoint)
		assert response.status_code == status.HTTP_401_UNAUTHORIZED
