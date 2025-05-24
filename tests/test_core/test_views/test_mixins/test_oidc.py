########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture, MockType

################################################################################
from tests.test_core.type_hints import LDAPConnectorMock
from core.views.mixins.ldap.user import LDAPUserMixin
from core.models.application import Application, ApplicationSecurityGroup
from core.models.user import User, USER_TYPE_LDAP, USER_TYPE_LOCAL
from core.views.mixins.oidc import get_user_groups
from interlock_backend.settings import OIDC_INTERLOCK_LOGIN_COOKIE
from core.constants.attrs.local import LOCAL_ATTR_USER_GROUPS, LOCAL_ATTR_DN
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
from django.http import HttpResponse
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from datetime import datetime, timedelta
from pytest_mock import MockerFixture
from urllib.parse import quote, parse_qs, urlparse
from core.views.mixins.oidc import (
	OidcAuthorizeMixin,
	OidcAuthorizeEndpoint,
	userinfo,
	CustomScopeClaims,
)
from oidc_provider.models import Client, UserConsent
from django.http import QueryDict
from typing import Protocol, Union
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from tests.test_core.conftest import RuntimeSettingsFactory

################################################################################
################################# FIXTURES #####################################
################################################################################


@pytest.fixture
def f_request(mocker: MockerFixture):
	m_request = mocker.Mock()
	m_request.META = {}
	m_request.GET = QueryDict(mutable=True)
	m_request.POST = QueryDict(mutable=True)
	return m_request


@pytest.fixture
def f_default_password():
	return "mockpassword"


@pytest.fixture
def f_user_local(
	f_default_password, f_runtime_settings: RuntimeSettingsSingleton
):
	"""Test creating a user with all fields"""
	m_user = User.objects.create(
		username="testuserlocal",
		password=f_default_password,
		email=f"testuserlocal@{f_runtime_settings.LDAP_DOMAIN}",
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
		_distinguished_name="cn=john,ou=users,dc=example,dc=com",
		user_type=USER_TYPE_LDAP,
		is_enabled=True,
	)
	return m_user


@pytest.fixture
def f_application():
	"""Fixture creating a test application in the database"""
	m_application = Application.objects.create(
		name="Test Application",
		enabled=True,
		client_id="test-client-id",
		client_secret="test-client-secret",
		redirect_uris="https://example.com/callback",
		scopes="openid profile",
	)
	return m_application


@pytest.fixture
def f_application_group(f_application, f_user_local, f_user_ldap):
	"""Fixture creating a test application group in the database"""
	m_asg = ApplicationSecurityGroup(
		application=f_application,
		ldap_objects=["some_group_dn"],
		enabled=True,
	)
	m_asg.save()
	m_asg.users.add(f_user_local)
	m_asg.users.add(f_user_ldap)
	m_asg.save()
	return m_asg


@pytest.fixture
def f_client(f_application) -> Union[MockType, Client]:
	m_client = Client.objects.create(
		client_id=f_application.client_id,
		redirect_uris=f_application.redirect_uris.split(","),
		require_consent=True,
		reuse_consent=True,
	)
	return m_client


@pytest.fixture(autouse=True)
def f_ldap_connector(g_ldap_connector) -> MockType:
	"""Fixture to mock LDAPConnector and its context manager."""
	return g_ldap_connector(patch_path="core.views.mixins.oidc.LDAPConnector")


@pytest.fixture(autouse=True)
def f_runtime_settings(g_runtime_settings: RuntimeSettingsFactory):
	return g_runtime_settings()


class OidcUriFactory(Protocol):
	def __call__(
		self,
		prompt=None,
		nonce=None,
		scope=None,
		response_type=None,
		client_id=None,
		redirect_uri=None,
	) -> str: ...


@pytest.fixture
def f_oidc_uri(f_runtime_settings) -> OidcUriFactory:
	def maker(**kwargs):
		base_url = f"https://interlock.{f_runtime_settings.LDAP_DOMAIN}/openid/authorize/?"
		params = []
		for kw, kwv in kwargs.items():
			if kwv:
				params.append(f"{kw}={quote(str(kwv))}")
		for i, p in enumerate(params):
			if i == 0:
				base_url += p
			else:
				base_url += f"&{p}"
		return base_url

	return maker


@pytest.fixture
def f_authorize_mixin(
	mocker: MockerFixture, f_user_local, f_request
) -> OidcAuthorizeMixin:
	mixin = OidcAuthorizeMixin()
	mixin.client_id = "test_client_id"
	mixin.request = f_request
	mixin.request.user = f_user_local
	mixin.request.get_full_path.return_value = "/test/path"
	mixin.authorize = mocker.MagicMock()
	return mixin


class ConsentFactory(Protocol):
	def __call__(
		self, date_given: datetime = None, expire_delta: dict = None
	) -> UserConsent: ...


@pytest.fixture
def f_consent(mocker: MockerFixture) -> MockType:
	def maker(date_given: datetime = None, expire_delta: dict = None):
		m_consent = mocker.MagicMock(spec=UserConsent)
		if expire_delta:
			m_consent.expires_at = timezone.make_aware(
				datetime.now() + timedelta(**expire_delta)
			)
		else:
			m_consent.expires_at = timezone.make_aware(
				datetime.now() + timedelta(days=1)
			)
		if date_given:
			m_consent.date_given = date_given
		else:
			m_consent.date_given = timezone.make_aware(datetime.now())
		return m_consent

	return maker


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
	f_application,
	f_application_group: ApplicationSecurityGroup,
):
	assert get_user_groups(user=f_user_local) == [
		str(f_application_group.uuid)
	]

@pytest.mark.django_db
def test_get_user_groups_ldap_user(
	mocker: MockerFixture,
	f_user_ldap: User,
	f_application_group: ApplicationSecurityGroup,
):
	m_ldap_user_attrs = {
		LOCAL_ATTR_USER_GROUPS: [
			{LOCAL_ATTR_DN: "some_group_dn"}
		]
	}
	m_ldap_user_mixin: LDAPUserMixin = mocker.MagicMock()
	m_ldap_user_mixin.ldap_user_fetch.return_value = m_ldap_user_attrs
	mocker.patch(
		"core.views.mixins.oidc.LDAPUserMixin",
		return_value=m_ldap_user_mixin,
	)
	assert get_user_groups(user=f_user_ldap) == ["some_group_dn"]


@pytest.mark.django_db
def test_userinfo(mocker: MockerFixture, f_user_local: User):
	m_claims = {}
	m_groups = ["mock_group_list"]
	m_get_user_groups = mocker.patch(
		"core.views.mixins.oidc.get_user_groups", return_value=m_groups
	)

	result = userinfo(m_claims, f_user_local)
	m_get_user_groups.assert_called_once_with(f_user_local)
	assert result["sub"] == f_user_local.username  # Subject identifier
	assert (
		result["preferred_username"] == f_user_local.username
	)  # Subject identifier
	assert result["username"] == f_user_local.username  # Subject identifier
	assert result["groups"] == m_groups


class TestCustomScopeClaims:
	@staticmethod
	def test_setup(mocker: MockerFixture):
		m_scope_claims = mocker.Mock()
		m_scope_claims.setup = CustomScopeClaims.setup
		m_scope_claims.setup(m_scope_claims)

		assert m_scope_claims.claims == {
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

	@staticmethod
	@pytest.mark.django_db
	@pytest.mark.parametrize(
		"scopes",
		(
			("profile"),
			("email"),
			("groups"),
		),
	)
	def test_create_response_dic(
		scopes: tuple[str], mocker: MockerFixture, f_user_local: User
	):
		m_super_method = mocker.patch(
			"core.views.mixins.oidc.ScopeClaims.create_response_dic",
			return_value={},
		)
		m_scope_claims = mocker.Mock(spec=CustomScopeClaims)
		m_scope_claims.user = f_user_local
		m_scope_claims.scopes = scopes
		m_scope_claims.create_response_dic = (
			CustomScopeClaims.create_response_dic
		)
		m_groups = ["mock_group_list"]
		m_get_user_groups = mocker.patch(
			"core.views.mixins.oidc.get_user_groups", return_value=m_groups
		)

		response_dict: dict = m_scope_claims.create_response_dic(m_scope_claims)
		m_super_method.assert_called_once()
		if scopes[0] == "profile":
			assert response_dict["username"] == f_user_local.username
		if scopes[0] in (
			"profile",
			"email",
		):
			assert response_dict["email"] == f_user_local.email
		if scopes[0] in (
			"profile",
			"groups",
		):
			assert response_dict["groups"] == m_groups


@pytest.mark.django_db
class TestSetExtraParams:
	@staticmethod
	def test_with_bool_value(f_authorize_mixin: OidcAuthorizeMixin) -> None:
		data = {"test_bool": True}
		login_url = "https://example.com/login"
		result = f_authorize_mixin.set_extra_params(data, login_url)
		assert "test_bool=true" in result

	@staticmethod
	def test_with_string_value(f_authorize_mixin: OidcAuthorizeMixin) -> None:
		data = {"test_str": "value with spaces"}
		login_url = "https://example.com/login"
		result = f_authorize_mixin.set_extra_params(data, login_url)
		assert "test_str=value%20with%20spaces" in result

	@staticmethod
	def test_with_number_value(f_authorize_mixin: OidcAuthorizeMixin) -> None:
		data = {"test_num": 123}
		login_url = "https://example.com/login"
		result = f_authorize_mixin.set_extra_params(data, login_url)
		assert "test_num=123" in result


@pytest.mark.django_db
class TestGetRelevantObjects:
	@staticmethod
	def test_successful_fetch(
		mocker: MockerFixture,
		f_authorize_mixin: OidcAuthorizeMixin,
		f_application: MockType,
		f_client: MockType,
		f_logger: MockType,
	) -> None:
		m_request = mocker.MagicMock()
		m_request.GET.get.return_value = "test_client_id"

		mocker.patch(
			"core.views.mixins.oidc.Application.objects.get",
			return_value=f_application,
		)
		mocker.patch(
			"core.views.mixins.oidc.Client.objects.get", return_value=f_client
		)

		result = f_authorize_mixin.get_relevant_objects(m_request)

		assert result is None
		assert f_authorize_mixin.client_id == "test_client_id"
		assert f_authorize_mixin.application == f_application
		assert f_authorize_mixin.client == f_client
		f_logger.exception.assert_not_called()

	@staticmethod
	def test_failed_fetch(
		mocker: MockerFixture,
		f_authorize_mixin: OidcAuthorizeMixin,
		f_logger: MockType,
	) -> None:
		m_request = mocker.MagicMock()
		m_request.GET.get.return_value = "invalid_client_id"

		mocker.patch(
			"core.views.mixins.oidc.Application.objects.get",
			side_effect=ObjectDoesNotExist,
		)

		result = f_authorize_mixin.get_relevant_objects(m_request)

		assert result is not None
		assert result.status_code == 302
		f_logger.exception.assert_called_once()


@pytest.mark.django_db
class TestUserRequiresConsent:
	@staticmethod
	def test_with_skip_consent(
		mocker: MockerFixture,
		f_authorize_mixin: OidcAuthorizeMixin,
		f_user_ldap: MockType,
		f_client: MockType,
	) -> None:
		mocker.patch("core.views.mixins.oidc.OIDC_SKIP_CUSTOM_CONSENT", True)
		f_authorize_mixin.client = f_client
		assert not f_authorize_mixin.user_requires_consent(f_user_ldap)

	@staticmethod
	def test_with_no_consent_required(
		mocker: MockerFixture,
		f_authorize_mixin: OidcAuthorizeMixin,
		f_user_ldap: MockType,
		f_client: MockType,
	) -> None:
		mocker.patch("core.views.mixins.oidc.OIDC_SKIP_CUSTOM_CONSENT", False)
		f_client.require_consent = False
		f_authorize_mixin.client = f_client
		assert not f_authorize_mixin.user_requires_consent(f_user_ldap)

	@staticmethod
	def test_with_valid_consent(
		mocker: MockerFixture,
		f_authorize_mixin: OidcAuthorizeMixin,
		f_user_ldap: MockType,
		f_client: MockType,
		f_consent: ConsentFactory,
	) -> None:
		mocker.patch("core.views.mixins.oidc.OIDC_SKIP_CUSTOM_CONSENT", False)
		f_authorize_mixin.client = f_client
		mocker.patch(
			"core.views.mixins.oidc.UserConsent.objects.get",
			return_value=f_consent(),
		)
		assert not f_authorize_mixin.user_requires_consent(f_user_ldap)

	@staticmethod
	def test_no_reuse_consent_but_user_just_consented(
		mocker: MockerFixture,
		f_authorize_mixin: OidcAuthorizeMixin,
		f_user_ldap: MockType,
		f_client: MockType,
		f_consent: ConsentFactory,
	) -> None:
		f_client.reuse_consent = False
		f_client.save()
		f_client.refresh_from_db()
		mocker.patch("core.views.mixins.oidc.OIDC_SKIP_CUSTOM_CONSENT", False)
		f_authorize_mixin.client = f_client
		mocker.patch(
			"core.views.mixins.oidc.UserConsent.objects.get",
			return_value=f_consent(
				date_given=timezone.make_aware(
					datetime.now() - timedelta(seconds=30)
				)
			),
		)
		assert not f_authorize_mixin.user_requires_consent(f_user_ldap)


@pytest.mark.django_db
class TestUserCanAccessApp:
	@staticmethod
	def test_with_no_security_group(
		mocker: MockerFixture,
		f_authorize_mixin: OidcAuthorizeMixin,
		f_user_ldap: MockType,
		f_application: MockType,
	) -> None:
		f_authorize_mixin.application = f_application
		mocker.patch(
			"core.views.mixins.oidc.ApplicationSecurityGroup.objects.get",
			side_effect=ObjectDoesNotExist,
		)
		assert f_authorize_mixin.user_can_access_app(f_user_ldap)

	@staticmethod
	def test_with_disabled_security_group(
		mocker: MockerFixture,
		f_authorize_mixin: OidcAuthorizeMixin,
		f_user_ldap: MockType,
		f_application: MockType,
		f_application_group: MockType,
	) -> None:
		f_authorize_mixin.application = f_application
		f_application_group.enabled = False
		mocker.patch(
			"core.views.mixins.oidc.ApplicationSecurityGroup.objects.get",
			return_value=f_application_group,
		)
		assert f_authorize_mixin.user_can_access_app(f_user_ldap)

	@staticmethod
	def test_user_not_in_group(
		mocker: MockerFixture,
		f_authorize_mixin: OidcAuthorizeMixin,
		f_user_ldap: MockType,
		f_ldap_connector: LDAPConnectorMock,
		f_application: MockType,
		f_application_group: MockType,
	) -> None:
		m_recursive_search = mocker.patch(
			"core.views.mixins.oidc.recursive_member_search", return_value=False
		)
		f_authorize_mixin.application = f_application
		assert f_authorize_mixin.user_can_access_app(f_user_ldap) is False
		m_recursive_search.assert_called_once_with(
			user_dn=f_user_ldap.distinguished_name,
			connection=f_ldap_connector.connection,
			group_dn="some_group_dn",
		)

	@staticmethod
	def test_user_in_group(
		f_authorize_mixin: OidcAuthorizeMixin,
		f_user_local: MockType,
		f_application: MockType,
		f_application_group: MockType,
	) -> None:
		f_authorize_mixin.application = f_application
		f_application_group.users.add(f_user_local)
		f_application_group.save()
		f_application_group.refresh_from_db()
		assert f_authorize_mixin.user_can_access_app(f_user_local)

	@staticmethod
	def test_with_ldap_user_access(
		mocker: MockerFixture,
		f_authorize_mixin: OidcAuthorizeMixin,
		f_user_ldap: MockType,
		f_application: MockType,
		f_security_group: MockType,
		f_ldap_connector: LDAPConnectorMock,
	) -> None:
		f_authorize_mixin.application = f_application
		mocker.patch(
			"core.views.mixins.oidc.ApplicationSecurityGroup.objects.get",
			return_value=f_security_group,
		)
		m_recursive_search = mocker.patch(
			"core.views.mixins.oidc.recursive_member_search", return_value=True
		)
		assert f_authorize_mixin.user_can_access_app(f_user_ldap)
		m_recursive_search.assert_called_once_with(
			user_dn=f_user_ldap.distinguished_name,
			connection=f_ldap_connector.connection,
			group_dn=f_security_group.ldap_objects[0],
		)
		f_ldap_connector.cls_mock.assert_called_once_with(force_admin=True)

	@staticmethod
	def test_ldap_user_cannot_access(
		mocker: MockerFixture,
		f_authorize_mixin: OidcAuthorizeMixin,
		f_user_ldap: MockType,
		f_application: MockType,
		f_security_group: MockType,
		f_ldap_connector: LDAPConnectorMock,
	):
		f_authorize_mixin.application = f_application
		mocker.patch(
			"core.views.mixins.oidc.ApplicationSecurityGroup.objects.get",
			return_value=f_security_group,
		)
		m_recursive_search = mocker.patch(
			"core.views.mixins.oidc.recursive_member_search", return_value=False
		)
		assert f_authorize_mixin.user_can_access_app(f_user_ldap) is False
		m_recursive_search.assert_called_once_with(
			user_dn=f_user_ldap.distinguished_name,
			connection=f_ldap_connector.connection,
			group_dn=f_security_group.ldap_objects[0],
		)
		f_ldap_connector.cls_mock.assert_called_once_with(force_admin=True)


@pytest.mark.django_db
class TestLoginRedirect:
	@staticmethod
	def test_successful_redirect(
		mocker: MockerFixture,
		f_authorize_mixin: OidcAuthorizeMixin,
		f_application: MockType,
		f_client: MockType,
		f_user_ldap: MockType,
	) -> None:
		f_authorize_mixin.application = f_application
		f_authorize_mixin.client = f_client
		f_authorize_mixin.request.user = f_user_ldap

		mocker.patch(
			"core.views.mixins.oidc.OidcAuthorizeMixin.get_login_url",
			return_value="https://example.com/login",
		)

		response = f_authorize_mixin.login_redirect()

		assert response.status_code == 302
		assert response.url == "https://example.com/login"


@pytest.mark.django_db
class TestAbortRedirect:
	@staticmethod
	def test_abort_response(
		mocker: MockerFixture, f_authorize_mixin: OidcAuthorizeMixin
	) -> None:
		m_response = mocker.MagicMock(spec=HttpResponse)
		result = f_authorize_mixin.abort_redirect(m_response)

		assert result == m_response
		m_response.set_cookie.assert_called_once()


@pytest.mark.django_db
class TestGetLoginUrl:
	@staticmethod
	def test_base_parameters(
		f_authorize_mixin: OidcAuthorizeMixin,
		f_application: MockType,
		f_client: MockType,
		f_user_ldap: MockType,
	) -> None:
		f_authorize_mixin.application = f_application
		f_authorize_mixin.client = f_client
		f_authorize_mixin.request.user = f_user_ldap

		login_url = f_authorize_mixin.get_login_url()
		parsed = urlparse(login_url)
		params = parse_qs(parsed.query)

		assert QK_NEXT in params
		assert params["application"][0] == f_application.name
		assert params["client_id"][0] == f_client.client_id
		assert params["redirect_uri"][0] == f_client.redirect_uris[0]

	@staticmethod
	@pytest.mark.parametrize(
		"prompt_value",
		[
			OIDC_PROMPT_NONE,
			OIDC_PROMPT_LOGIN,
			OIDC_PROMPT_CONSENT,
			OIDC_PROMPT_SELECT_ACCOUNT,
		],
	)
	def test_with_allowed_prompt_values(
		f_authorize_mixin: OidcAuthorizeMixin,
		f_application: MockType,
		f_client: MockType,
		f_oidc_uri: OidcUriFactory,
		prompt_value: str,
	) -> None:
		m_oidc_uri = f_oidc_uri(prompt=prompt_value)
		m_oidc_uri_qs = parse_qs(urlparse(m_oidc_uri).query)
		for _k, _q in m_oidc_uri_qs.items():
			if len(_q) == 1:
				m_oidc_uri_qs[_k] = _q[0]

		f_authorize_mixin.application = f_application
		f_authorize_mixin.client = f_client
		f_authorize_mixin.request.META["QUERY_STRING"] = m_oidc_uri
		f_authorize_mixin.request.GET = m_oidc_uri_qs
		f_authorize_mixin.authorize = OidcAuthorizeEndpoint(
			f_authorize_mixin.request
		)

		login_url = f_authorize_mixin.get_login_url()
		params = parse_qs(urlparse(login_url).query)

		assert params["prompt"][0] == prompt_value

	@staticmethod
	def test_with_oidc_attrs_parameters(
		f_authorize_mixin: OidcAuthorizeMixin,
		f_application: MockType,
		f_client: MockType,
		f_oidc_uri: OidcUriFactory,
	) -> None:
		f_authorize_mixin.application = f_application
		f_authorize_mixin.client = f_client
		m_oidc_uri = f_oidc_uri(
			response_type="id_token",
			prompt=OIDC_PROMPT_CONSENT,
			nonce=12345,
			redirect_uri=f_application.redirect_uris,
			scope="profile",
			client_id=f_application.client_id,
		)
		m_oidc_uri_qs = parse_qs(urlparse(m_oidc_uri).query)
		for _k, _q in m_oidc_uri_qs.items():
			if len(_q) == 1:
				m_oidc_uri_qs[_k] = _q[0]

		f_authorize_mixin.request.META["QUERY_STRING"] = m_oidc_uri
		f_authorize_mixin.request.GET = m_oidc_uri_qs
		f_authorize_mixin.authorize = OidcAuthorizeEndpoint(
			f_authorize_mixin.request
		)

		login_url = f_authorize_mixin.get_login_url()
		params = parse_qs(urlparse(login_url).query)

		assert params["response_type"][0] == "id_token"
		assert params["prompt"][0] == OIDC_PROMPT_CONSENT
		assert int(params["nonce"][0]) == 12345
		assert (
			params["redirect_uri"][0]
			== f_authorize_mixin.application.redirect_uris
		)
		assert params["scope"][0] == "profile"
		assert params["client_id"][0] == f_authorize_mixin.application.client_id
		assert (
			f_authorize_mixin.application.client_id
			== f_authorize_mixin.client.client_id
		)


@pytest.mark.django_db
class TestLoginRedirect:
	@staticmethod
	def test_cookie_settings(
		mocker: MockerFixture,
		f_authorize_mixin: OidcAuthorizeMixin,
		f_application: MockType,
		f_client: MockType,
	) -> None:
		f_authorize_mixin.application = f_application
		f_authorize_mixin.client = f_client
		mocker.patch.object(
			f_authorize_mixin, "get_login_url", return_value="/login"
		)

		response = f_authorize_mixin.login_redirect()

		assert response.status_code == 302
		assert (
			response.cookies.get(OIDC_INTERLOCK_LOGIN_COOKIE).value
			== OIDC_COOKIE_VUE_LOGIN
		)


@pytest.mark.django_db
class TestAbortRedirect:
	@staticmethod
	def test_abort_cookie_settings(
		mocker: MockerFixture, f_authorize_mixin: OidcAuthorizeMixin
	) -> None:
		mock_response = mocker.MagicMock(spec=HttpResponse)
		response = f_authorize_mixin.abort_redirect(mock_response)

		assert response == mock_response
		cookie_call = mock_response.set_cookie.call_args
		assert cookie_call.kwargs["value"] == OIDC_COOKIE_VUE_ABORT


@pytest.mark.django_db
class TestGetRelevantObjectsErrorHandling:
	@staticmethod
	def test_error_redirect_parameters(
		mocker: MockerFixture,
		f_authorize_mixin: OidcAuthorizeMixin,
		f_logger: MockType,
	) -> None:
		mocker.patch(
			"core.views.mixins.oidc.Application.objects.get",
			side_effect=ObjectDoesNotExist,
		)

		response = f_authorize_mixin.get_relevant_objects(
			f_authorize_mixin.request
		)
		parsed = urlparse(response.url)
		params = parse_qs(parsed.query)

		assert params[QK_ERROR][0] == "true"
		assert params[QK_ERROR_DETAIL][0] == "oidc_application_fetch"
		f_logger.exception.assert_called_once()


def test_required_constants_present() -> None:
	assert QK_ERROR == "error"
	assert QK_ERROR_DETAIL == "error_detail"
	assert QK_NEXT == "next"
	assert OIDC_COOKIE_VUE_LOGIN == "login"
	assert OIDC_COOKIE_VUE_ABORT == "abort"


def test_oidc_attrs_completeness() -> None:
	required_attrs = {
		"client_id",
		"redirect_uri",
		"response_type",
		"scope",
		"nonce",
		"prompt",
		"code_challenge",
		"code_challenge_method",
	}
	assert set(OIDC_ATTRS) == required_attrs
