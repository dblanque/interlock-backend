########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture

################################################################################
from core.models.user import User
from tests.test_core.test_views.conftest import APIClientFactory
from tests.test_core.conftest import ConnectorFactory, LDAPConnectorMock
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
from core.views.auth import LinuxPamView
from core.exceptions.base import BadRequest, Unauthorized, PermissionDenied
from core.constants.attrs.local import LOCAL_ATTR_USERNAME, LOCAL_ATTR_PASSWORD
from typing import Protocol


@pytest.fixture
def f_ldap_connector(g_ldap_connector: ConnectorFactory):
	return g_ldap_connector(patch_path="core.views.auth.LDAPConnector")


class IsLdapBackendEnabledProtocol(Protocol):
	def __call__(self, enabled=False, **kwargs): ...


@pytest.fixture
def f_mock_ldap_backend_enabled(
	mocker: MockerFixture,
) -> IsLdapBackendEnabledProtocol:
	def maker(enabled=False, **kwargs):
		return mocker.patch(
			"core.views.auth.is_ldap_backend_enabled",
			return_value=enabled,
		)

	return maker


class TestLinuxPamViewValidate:
	instance = LinuxPamView()

	def test_no_data_raises_bad_request(self):
		with pytest.raises(BadRequest):
			self.instance.validate(data=None)

	def test_raises_bad_cross_check_key(
		self,
		mocker: MockerFixture,
	):
		m_fernet_decrypt = mocker.patch(
			"core.views.auth.fernet_decrypt",
			side_effect=Exception("Some Decrypt Error."),
		)

		with pytest.raises(BadRequest) as e:
			self.instance.validate(data={"cross_check_key": "bad_value"})

		m_fernet_decrypt.assert_called_once_with("bad_value")
		errors = e.value.detail.get("errors")
		assert isinstance(errors, dict)
		assert "cross_check_key" in errors.keys()
		assert "could not be decrypted" in errors.get("cross_check_key", "")

	def test_raises_cross_check_key_required(
		self,
		mocker: MockerFixture,
	):
		m_fernet_decrypt = mocker.patch(
			"core.views.auth.fernet_decrypt",
			side_effect=Exception("Some Decrypt Error."),
		)

		with pytest.raises(BadRequest) as e:
			self.instance.validate(data={})

		m_fernet_decrypt.assert_not_called()
		errors = e.value.detail.get("errors")
		assert isinstance(errors, dict)
		assert "cross_check_key" in errors.keys()
		assert "key required" in errors.get("cross_check_key", "")

	@pytest.mark.parametrize(
		"remove_field",
		(
			LOCAL_ATTR_USERNAME,
			LOCAL_ATTR_PASSWORD,
		),
	)
	def test_raises_missing_str_field(
		self,
		mocker: MockerFixture,
		remove_field: str,
	):
		m_fernet_decrypt = mocker.patch(
			"core.views.auth.fernet_decrypt", return_value="mock_result_check"
		)
		m_data = {
			LOCAL_ATTR_USERNAME: "testuser",
			LOCAL_ATTR_PASSWORD: "mockpassword",
			"cross_check_key": "mock_key",
		}
		if remove_field in m_data:
			del m_data[remove_field]

		with pytest.raises(BadRequest) as e:
			self.instance.validate(data=m_data)

		m_fernet_decrypt.assert_called_once_with("mock_key")
		errors = e.value.detail.get("errors")
		assert isinstance(errors, dict)
		assert remove_field in errors.keys()

	@pytest.mark.parametrize(
		"totp_code",
		(
			"abcdef",
			"12345a",
			"123456-",
		),
	)
	def test_totp_validation(
		self,
		mocker: MockerFixture,
		totp_code: str | int,
	):
		m_fernet_decrypt = mocker.patch(
			"core.views.auth.fernet_decrypt", return_value="mock_result_check"
		)
		m_data = {
			LOCAL_ATTR_USERNAME: "testuser",
			LOCAL_ATTR_PASSWORD: "mockpassword",
			"totp_code": totp_code,
			"cross_check_key": "mock_key",
		}

		with pytest.raises(BadRequest) as e:
			self.instance.validate(data=m_data)

		m_fernet_decrypt.assert_called_once_with("mock_key")
		errors = e.value.detail.get("errors")
		assert isinstance(errors, dict)
		assert "totp_code" in errors.keys()

	@pytest.mark.parametrize(
		"totp_code",
		(
			"012345",
			"123456",
			123456,
		),
	)
	def test_success(
		self,
		mocker: MockerFixture,
		totp_code: str | int,
	):
		m_fernet_decrypt = mocker.patch(
			"core.views.auth.fernet_decrypt", return_value="mock_result_check"
		)
		m_data = {
			LOCAL_ATTR_USERNAME: "testuser",
			LOCAL_ATTR_PASSWORD: "mockpassword",
			"totp_code": totp_code,
			"cross_check_key": "mock_key",
		}

		result = self.instance.validate(data=m_data)

		assert isinstance(result, dict)
		assert "unsafe" not in result
		for k in (
			LOCAL_ATTR_USERNAME,
			LOCAL_ATTR_PASSWORD,
			"totp_code",
			"cross_check_key",
		):
			assert k in result
		m_fernet_decrypt.assert_called_once_with("mock_key")


class TestLinuxPamViewGet:
	def test_success_local(
		self,
		mocker: MockerFixture,
		f_user_local: User,
		f_mock_ldap_backend_enabled: IsLdapBackendEnabledProtocol,
	):
		f_mock_ldap_backend_enabled(enabled=False)
		mocker.patch(
			"core.views.auth.settings.LINUX_PAM_AUTH_ENDPOINT_ADMIN_ONLY",
			False,
		)
		m_data = {
			LOCAL_ATTR_USERNAME: f_user_local.username,
			LOCAL_ATTR_PASSWORD: f_user_local.raw_password,  # type: ignore
			"cross_check_key": "mock_key",
		}
		m_request = mocker.Mock()
		m_request.data = m_data
		m_view = LinuxPamView()
		m_validate = mocker.patch.object(
			m_view, "validate", return_value=m_data
		)

		# Execution
		response: Response = m_view.get(request=m_request)

		# Assertion
		m_validate.assert_called_once_with(data=m_data)
		assert response.status_code == status.HTTP_200_OK

	def test_unauthorized_local(
		self,
		mocker: MockerFixture,
		f_user_local: User,
		f_mock_ldap_backend_enabled: IsLdapBackendEnabledProtocol,
	):
		f_mock_ldap_backend_enabled(enabled=False)
		mocker.patch(
			"core.views.auth.settings.LINUX_PAM_AUTH_ENDPOINT_ADMIN_ONLY",
			False,
		)
		m_data = {
			LOCAL_ATTR_USERNAME: f_user_local.username,
			LOCAL_ATTR_PASSWORD: f_user_local.raw_password,  # type: ignore
			"cross_check_key": "mock_key",
		}
		m_request = mocker.Mock()
		m_request.data = m_data
		m_view = LinuxPamView()
		m_validate = mocker.patch.object(
			m_view, "validate", return_value=m_data
		)

		# Execution
		response: Response = m_view.get(request=m_request)

		# Assertion
		m_validate.assert_called_once_with(data=m_data)
		assert response.status_code == status.HTTP_200_OK

	def test_permission_denied_local(
		self,
		mocker: MockerFixture,
		f_user_local: User,
		f_mock_ldap_backend_enabled: IsLdapBackendEnabledProtocol,
	):
		f_mock_ldap_backend_enabled(enabled=False)
		mocker.patch(
			"core.views.auth.settings.LINUX_PAM_AUTH_ENDPOINT_ADMIN_ONLY",
			True,
		)
		m_data = {
			LOCAL_ATTR_USERNAME: f_user_local.username,
			LOCAL_ATTR_PASSWORD: f_user_local.raw_password,  # type: ignore
			"cross_check_key": "mock_key",
		}
		m_request = mocker.Mock()
		m_request.data = m_data
		m_view = LinuxPamView()
		m_validate = mocker.patch.object(
			m_view, "validate", return_value=m_data
		)

		# Execution
		with pytest.raises(PermissionDenied) as e:
			m_view.get(request=m_request)
		response: Response = e.value

		# Assertion
		m_validate.assert_called_once_with(data=m_data)
		assert response.status_code == status.HTTP_403_FORBIDDEN

	def test_success_ldap(
		self,
		mocker: MockerFixture,
		f_user_ldap: User,
		f_ldap_connector: LDAPConnectorMock,
		f_mock_ldap_backend_enabled: IsLdapBackendEnabledProtocol,
	):
		f_mock_ldap_backend_enabled(enabled=True)
		mocker.patch(
			"core.views.auth.settings.LINUX_PAM_AUTH_ENDPOINT_ADMIN_ONLY",
			False,
		)
		m_get_user = mocker.patch.object(
			f_ldap_connector,
			"get_user",
			return_value=f_user_ldap,
		)
		m_data = {
			LOCAL_ATTR_USERNAME: f_user_ldap.username,
			LOCAL_ATTR_PASSWORD: f_user_ldap.raw_password,  # type: ignore
			"cross_check_key": "mock_key",
		}
		m_request = mocker.Mock()
		m_request.data = m_data
		m_view = LinuxPamView()
		m_validate = mocker.patch.object(
			m_view, "validate", return_value=m_data
		)

		# Execution
		response: Response = m_view.get(request=m_request)

		# Assertion
		m_validate.assert_called_once_with(data=m_data)
		m_get_user.assert_called_once_with(username=f_user_ldap.username)
		f_ldap_connector.rebind.assert_called_once_with(  # type: ignore
			user_dn=f_user_ldap.distinguished_name,
			password=f_user_ldap.raw_password,  # type: ignore
		)
		assert response.status_code == status.HTTP_200_OK

	def test_unauthorized_ldap(
		self,
		mocker: MockerFixture,
		f_user_ldap: User,
		f_ldap_connector: LDAPConnectorMock,
		f_mock_ldap_backend_enabled: IsLdapBackendEnabledProtocol,
	):
		f_mock_ldap_backend_enabled(enabled=True)
		mocker.patch(
			"core.views.auth.settings.LINUX_PAM_AUTH_ENDPOINT_ADMIN_ONLY",
			False,
		)
		m_get_user = mocker.patch.object(
			f_ldap_connector,
			"get_user",
			return_value=f_user_ldap,
		)
		f_ldap_connector.rebind.return_value = None  # type: ignore
		m_data = {
			LOCAL_ATTR_USERNAME: f_user_ldap.username,
			LOCAL_ATTR_PASSWORD: f_user_ldap.raw_password,  # type: ignore
			"cross_check_key": "mock_key",
		}
		m_request = mocker.Mock()
		m_request.data = m_data
		m_view = LinuxPamView()
		m_validate = mocker.patch.object(
			m_view, "validate", return_value=m_data
		)

		# Execution
		with pytest.raises(Unauthorized) as e:
			m_view.get(request=m_request)
		response: Response = e.value

		# Assertion
		m_validate.assert_called_once_with(data=m_data)
		m_get_user.assert_called_once_with(username=f_user_ldap.username)
		f_ldap_connector.rebind.assert_called_once_with(  # type: ignore
			user_dn=f_user_ldap.distinguished_name,
			password=f_user_ldap.raw_password,  # type: ignore
		)
		assert response.status_code == status.HTTP_401_UNAUTHORIZED

	def test_permission_denied_ldap(
		self,
		mocker: MockerFixture,
		f_user_ldap: User,
		f_ldap_connector: LDAPConnectorMock,
		f_mock_ldap_backend_enabled: IsLdapBackendEnabledProtocol,
	):
		f_mock_ldap_backend_enabled(enabled=True)
		mocker.patch(
			"core.views.auth.settings.LINUX_PAM_AUTH_ENDPOINT_ADMIN_ONLY",
			True,
		)
		m_data = {
			LOCAL_ATTR_USERNAME: f_user_ldap.username,
			LOCAL_ATTR_PASSWORD: f_user_ldap.raw_password,  # type: ignore
			"cross_check_key": "mock_key",
		}
		m_get_user = mocker.patch.object(
			f_ldap_connector,
			"get_user",
			return_value=f_user_ldap,
		)
		mocker.patch.object(f_ldap_connector, "rebind", return_value=True)
		m_request = mocker.Mock()
		m_request.data = m_data
		m_view = LinuxPamView()
		m_validate = mocker.patch.object(
			m_view, "validate", return_value=m_data
		)

		# Execution
		with pytest.raises(PermissionDenied) as e:
			m_view.get(request=m_request)
		response: Response = e.value

		# Assertion
		m_validate.assert_called_once_with(data=m_data)
		m_get_user.assert_called_once_with(username=f_user_ldap.username)
		f_ldap_connector.rebind.assert_called_once_with(  # type: ignore
			user_dn=f_user_ldap.distinguished_name,
			password=f_user_ldap.raw_password,  # type: ignore
		)
		assert response.status_code == status.HTTP_403_FORBIDDEN


class TestLinuxPamViewPost:
	def test_success(self, mocker: MockerFixture):
		m_request = mocker.Mock()
		m_get = mocker.patch.object(LinuxPamView, "get")
		m_view = LinuxPamView()
		m_view.post(request=m_request)
		m_get.assert_called_once_with(request=m_request, format=None)


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
