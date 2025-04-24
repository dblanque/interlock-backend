########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType
################################################################################
from core.views.mixins.ldap.user import UserViewLDAPMixin
from core.models.application import Application, ApplicationSecurityGroup
from core.models.user import User, USER_TYPE_LDAP, USER_TYPE_LOCAL
from core.views.mixins.oidc import (
	get_user_groups
)
from core.constants.oidc import (
	QK_NEXT,
	OIDC_PROMPT_NONE,
	OIDC_PROMPT_LOGIN,
	OIDC_PROMPT_CONSENT,
	OIDC_PROMPT_SELECT_ACCOUNT,
	OIDC_ATTRS,
	OIDC_COOKIE_VUE_LOGIN,
	OIDC_COOKIE_VUE_ABORT,
	QK_ERROR, 
	QK_ERROR_DETAIL,
)
from django.http import HttpRequest, HttpResponse
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from datetime import datetime, timedelta
from pytest_mock import MockerFixture
from urllib.parse import quote, parse_qs, urlparse
from core.views.mixins.oidc import OidcAuthorizeMixin
from oidc_provider.models import Client, UserConsent
from core.ldap.connector import LDAPConnector

################################################################################
################################# FIXTURES #####################################
################################################################################

@pytest.fixture
def f_default_password():
	return "mockpassword"

@pytest.fixture
def f_user_local(f_default_password):
	"""Test creating a user with all fields"""
	m_user = User.objects.create(
		username="testuserlocal",
		password=f_default_password,
		user_type=USER_TYPE_LOCAL,
		is_enabled=True,
	)
	return m_user

@pytest.fixture
def f_user_ldap(f_default_password):
	"""Test creating a user with all fields"""
	m_user = User.objects.create(
		username="testuserldap",
		password=f_default_password,
		dn="cn=john,ou=users,dc=example,dc=com",
		user_type=USER_TYPE_LDAP,
		is_enabled=True,
	)
	return m_user

@pytest.fixture(autouse=True)
def f_application():
	"""Fixture creating a test application in the database"""
	m_application = Application.objects.create(
		name="Test Application",
		enabled=True,
		client_id="test-client-id",
		client_secret="test-client-secret",
		redirect_uris="http://localhost:8000/callback",
		scopes="openid profile",
	)
	return m_application

@pytest.fixture(autouse=True)
def f_application_group(f_application, f_user_local, f_user_ldap):
	"""Fixture creating a test application group in the database"""
	m_asg = ApplicationSecurityGroup.objects.create(
		application=f_application,
		ldap_objects=["some_group_dn"],
		enabled=True,
	)
	m_asg.users.add(f_user_local)
	m_asg.users.add(f_user_ldap)
	return m_asg

@pytest.fixture(autouse=True)
def f_ldap_connector(g_ldap_connector) -> MockType:
	"""Fixture to mock LDAPConnector and its context manager."""
	return g_ldap_connector(patch_path="core.views.mixins.oidc.LDAPConnector")

@pytest.fixture(autouse=True)
def f_runtime_settings(g_runtime_settings):
	return g_runtime_settings

@pytest.fixture
def f_mixin(mocker: MockerFixture) -> OidcAuthorizeMixin:
	mixin = OidcAuthorizeMixin()
	mixin.client_id = "test_client_id"
	mixin.request = mocker.MagicMock(spec=HttpRequest)
	mixin.request.user = mocker.MagicMock(spec=User)
	mixin.request.get_full_path.return_value = "/test/path"
	mixin.authorize = mocker.MagicMock()
	return mixin

@pytest.fixture
def f_client() -> MockType:
	m_client = Client.objects.create(
		client_id="test_client_id",
		redirect_uris = ["https://example.com/callback"],
		require_consent = True,
		reuse_consent = True,
	)
	return m_client

@pytest.fixture
def f_user(mocker: MockerFixture) -> MockType:
	m_user = mocker.MagicMock(spec=User)
	m_user.id = 1
	m_user.user_type = USER_TYPE_LDAP
	m_user.dn = "cn=testuser,dc=example,dc=com"
	return m_user

@pytest.fixture
def f_consent(mocker: MockerFixture) -> MockType:
	m_consent = mocker.MagicMock(spec=UserConsent)
	m_consent.expires_at = timezone.make_aware(datetime.now() + timedelta(days=1))
	m_consent.date_given = timezone.make_aware(datetime.now())
	return m_consent

@pytest.fixture
def f_security_group(mocker: MockerFixture) -> MockType:
	m_group = mocker.MagicMock(spec=ApplicationSecurityGroup)
	m_group.enabled = True
	m_group.ldap_objects = ["cn=testgroup,dc=example,dc=com"]
	return m_group

@pytest.fixture
def f_logger(mocker: MockerFixture) -> MockType:
	return mocker.patch("core.views.mixins.oidc.logger")

################################################################################
################################### TESTS ######################################
################################################################################

@pytest.mark.django_db
def test_get_user_groups_local_user(
	f_user_local: User,
	f_application_group: ApplicationSecurityGroup
):
	assert get_user_groups(user=f_user_local) == [ f_application_group.uuid ]

@pytest.mark.django_db
def test_get_user_groups_ldap_user(
	mocker: MockerFixture,
	f_user_ldap: User,
	f_application_group: ApplicationSecurityGroup,
):
	m_ldap_user_attrs = {
		"memberOfObjects":[{"distinguishedName":"some_group_dn"}]
	}
	m_ldap_user_mixin: UserViewLDAPMixin = mocker.MagicMock()
	m_ldap_user_mixin.ldap_user_fetch.return_value = m_ldap_user_attrs
	mocker.patch(
		"core.views.mixins.oidc.UserViewLDAPMixin",
		return_value=m_ldap_user_mixin
	)
	assert get_user_groups(user=f_user_ldap) == [ "some_group_dn" ]

# -------------------------------- TEST CLASSES --------------------------------#

@pytest.mark.django_db
class TestSetExtraParams:
	@staticmethod
	def test_with_bool_value(f_mixin: OidcAuthorizeMixin) -> None:
		data = {"test_bool": True}
		login_url = "https://example.com/login"
		result = f_mixin.set_extra_params(data, login_url)
		assert "test_bool=true" in result

	@staticmethod
	def test_with_string_value(f_mixin: OidcAuthorizeMixin) -> None:
		data = {"test_str": "value with spaces"}
		login_url = "https://example.com/login"
		result = f_mixin.set_extra_params(data, login_url)
		assert "test_str=value%20with%20spaces" in result

	@staticmethod
	def test_with_number_value(f_mixin: OidcAuthorizeMixin) -> None:
		data = {"test_num": 123}
		login_url = "https://example.com/login"
		result = f_mixin.set_extra_params(data, login_url)
		assert "test_num=123" in result

@pytest.mark.django_db
class TestGetRelevantObjects:
	@staticmethod
	def test_successful_fetch(
		mocker: MockerFixture,
		f_mixin: OidcAuthorizeMixin,
		f_application: MockType,
		f_client: MockType,
		f_logger: MockType,
	) -> None:
		m_request = mocker.MagicMock()
		m_request.GET.get.return_value = "test_client_id"
		
		mocker.patch(
			"core.views.mixins.oidc.Application.objects.get",
			return_value=f_application
		)
		mocker.patch(
			"core.views.mixins.oidc.Client.objects.get",
			return_value=f_client
		)
		
		result = f_mixin.get_relevant_objects(m_request)
		
		assert result is None
		assert f_mixin.client_id == "test_client_id"
		assert f_mixin.application == f_application
		assert f_mixin.client == f_client
		f_logger.exception.assert_not_called()

	@staticmethod
	def test_failed_fetch(
		mocker: MockerFixture,
		f_mixin: OidcAuthorizeMixin,
		f_logger: MockType
	) -> None:
		m_request = mocker.MagicMock()
		m_request.GET.get.return_value = "invalid_client_id"
		
		mocker.patch(
			"core.views.mixins.oidc.Application.objects.get",
			side_effect=ObjectDoesNotExist
		)
		
		result = f_mixin.get_relevant_objects(m_request)
		
		assert result is not None
		assert result.status_code == 302
		f_logger.exception.assert_called_once()

@pytest.mark.django_db
class TestUserRequiresConsent:
	@staticmethod
	def test_with_skip_consent(
		mocker: MockerFixture,
		f_mixin: OidcAuthorizeMixin,
		f_user: MockType,
		f_client: MockType,
	) -> None:
		mocker.patch(
			"core.views.mixins.oidc.OIDC_SKIP_CUSTOM_CONSENT",
			True
		)
		f_mixin.client = f_client
		assert not f_mixin.user_requires_consent(f_user)

	@staticmethod
	def test_with_no_consent_required(
		mocker: MockerFixture,
		f_mixin: OidcAuthorizeMixin,
		f_user: MockType,
		f_client: MockType,
	) -> None:
		mocker.patch(
			"core.views.mixins.oidc.OIDC_SKIP_CUSTOM_CONSENT",
			False
		)
		f_client.require_consent = False
		f_mixin.client = f_client
		assert not f_mixin.user_requires_consent(f_user)

	@staticmethod
	def test_with_valid_consent(
		mocker: MockerFixture,
		f_mixin: OidcAuthorizeMixin,
		f_user: MockType,
		f_client: MockType,
		f_consent: MockType,
	) -> None:
		mocker.patch(
			"core.views.mixins.oidc.OIDC_SKIP_CUSTOM_CONSENT",
			False
		)
		f_mixin.client = f_client
		mocker.patch(
			"core.views.mixins.oidc.UserConsent.objects.get",
			return_value=f_consent
		)
		assert not f_mixin.user_requires_consent(f_user)

@pytest.mark.django_db
class TestUserCanAccessApp:
	@staticmethod
	def test_with_no_security_group(
		mocker: MockerFixture,
		f_mixin: OidcAuthorizeMixin,
		f_user: MockType,
		f_application: MockType,
	) -> None:
		f_mixin.application = f_application
		mocker.patch(
			"core.views.mixins.oidc.ApplicationSecurityGroup.objects.get",
			side_effect=ObjectDoesNotExist
		)
		assert f_mixin.user_can_access_app(f_user)

	@staticmethod
	def test_with_ldap_user_access(
		mocker: MockerFixture,
		f_mixin: OidcAuthorizeMixin,
		f_user: MockType,
		f_application: MockType,
		f_security_group: MockType,
		f_ldap_connector: LDAPConnector,
	) -> None:
		f_mixin.application = f_application
		mocker.patch(
			"core.views.mixins.oidc.ApplicationSecurityGroup.objects.get",
			return_value=f_security_group
		)
		mocker.patch(
			"core.views.mixins.oidc.recursive_member_search",
			return_value=True
		)
		assert f_mixin.user_can_access_app(f_user)
		f_ldap_connector.cls_mock.assert_called_once_with(force_admin=True)

@pytest.mark.django_db
class TestLoginRedirect:
	@staticmethod
	def test_successful_redirect(
		mocker: MockerFixture,
		f_mixin: OidcAuthorizeMixin,
		f_application: MockType,
		f_client: MockType,
		f_user: MockType,
	) -> None:
		f_mixin.application = f_application
		f_mixin.client = f_client
		f_mixin.request.user = f_user
		
		mocker.patch(
			"core.views.mixins.oidc.OidcAuthorizeMixin.get_login_url",
			return_value="https://example.com/login"
		)
		
		response = f_mixin.login_redirect()
		
		assert response.status_code == 302
		assert response.url == "https://example.com/login"

@pytest.mark.django_db
class TestAbortRedirect:
	@staticmethod
	def test_abort_response(
		mocker: MockerFixture,
		f_mixin: OidcAuthorizeMixin
	) -> None:
		m_response = mocker.MagicMock(spec=HttpResponse)
		result = f_mixin.abort_redirect(m_response)
		
		assert result == m_response
		m_response.set_cookie.assert_called_once()

@pytest.mark.django_db
class TestGetLoginUrl:
	@staticmethod
	def test_base_parameters(
		f_mixin: OidcAuthorizeMixin,
		f_application: MockType,
		f_client: MockType,
		f_user: MockType
	) -> None:
		f_mixin.application = f_application
		f_mixin.client = f_client
		f_mixin.request.user = f_user
		
		login_url = f_mixin.get_login_url()
		parsed = urlparse(login_url)
		params = parse_qs(parsed.query)

		assert QK_NEXT in params
		assert params["application"][0] == f_application.name
		assert params["client_id"][0] == f_client.client_id
		assert params["redirect_uri"][0] == f_client.redirect_uris[0]

	@staticmethod
	@pytest.mark.parametrize("prompt_value", [
		OIDC_PROMPT_NONE,
		OIDC_PROMPT_LOGIN,
		OIDC_PROMPT_CONSENT,
		OIDC_PROMPT_SELECT_ACCOUNT
	])
	def test_with_allowed_prompt_values(
		f_mixin: OidcAuthorizeMixin,
		f_application: MockType,
		f_client: MockType,
		prompt_value: str
	) -> None:
		f_mixin.application = f_application
		f_mixin.client = f_client
		f_mixin.authorize.params["prompt"] = prompt_value
		
		login_url = f_mixin.get_login_url()
		params = parse_qs(urlparse(login_url).query)

		assert params["prompt"][0] == prompt_value

	@staticmethod
	def test_with_oidc_attrs_parameters(
		f_mixin: OidcAuthorizeMixin,
		f_application: MockType,
		f_client: MockType
	) -> None:
		f_mixin.application = f_application
		f_mixin.client = f_client
		for attr in OIDC_ATTRS:
			if attr not in ["client_id", "redirect_uri"]:  # Already tested
				f_mixin.authorize.params[attr] = f"test_{attr}"
		
		login_url = f_mixin.get_login_url()
		params = parse_qs(urlparse(login_url).query)
		
		for attr in OIDC_ATTRS:
			if attr in ["client_id", "redirect_uri"]:
				continue
			assert params[attr][0] == f"test_{attr}"

@pytest.mark.django_db
class TestLoginRedirect:
	@staticmethod
	def test_cookie_settings(
		mocker: MockerFixture,
		f_mixin: OidcAuthorizeMixin,
		f_application: MockType,
		f_client: MockType
	) -> None:
		f_mixin.application = f_application
		f_mixin.client = f_client
		mocker.patch.object(f_mixin, 'get_login_url', return_value="/login")
		
		response = f_mixin.login_redirect()
		
		assert response.status_code == 302
		cookie_call = response.set_cookie.call_args
		assert cookie_call.kwargs["key"] == "oidc_interlock_login"
		assert cookie_call.kwargs["value"] == OIDC_COOKIE_VUE_LOGIN
		assert cookie_call.kwargs["httponly"] is True

@pytest.mark.django_db
class TestAbortRedirect:
	@staticmethod
	def test_abort_cookie_settings(mocker: MockerFixture, f_mixin: OidcAuthorizeMixin) -> None:
		mock_response = mocker.MagicMock(spec=HttpResponse)
		response = f_mixin.abort_redirect(mock_response)
		
		assert response == mock_response
		cookie_call = mock_response.set_cookie.call_args
		assert cookie_call.kwargs["value"] == OIDC_COOKIE_VUE_ABORT

@pytest.mark.django_db
class TestGetRelevantObjectsErrorHandling:
	@staticmethod
	def test_error_redirect_parameters(
		mocker: MockerFixture,
		f_mixin: OidcAuthorizeMixin,
		f_logger: MockType
	) -> None:
		mocker.patch(
			"core.views.mixins.oidc.Application.objects.get",
			side_effect=ObjectDoesNotExist
		)
		
		response = f_mixin.get_relevant_objects(f_mixin.request)
		parsed = urlparse(response.url)
		params = parse_qs(parsed.query)
		
		assert params[QK_ERROR][0] == "true"
		assert params[QK_ERROR_DETAIL][0] == "oidc_application_fetch"
		f_logger.exception.assert_called_once()

# ----------------------- CONSTANTS VALIDATION TESTS --------------------------#

class TestOidcConstants:
	@staticmethod
	def test_required_constants_present() -> None:
		assert QK_ERROR == "error"
		assert QK_ERROR_DETAIL == "error_detail"
		assert QK_NEXT == "next"
		assert OIDC_COOKIE_VUE_LOGIN == "login"
		assert OIDC_COOKIE_VUE_ABORT == "abort"

	@staticmethod
	def test_oidc_attrs_completeness() -> None:
		required_attrs = {
			"client_id", "redirect_uri", "response_type", "scope",
			"nonce", "prompt", "code_challenge", "code_challenge_method"
		}
		assert set(OIDC_ATTRS) == required_attrs
