########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture

################################################################################
from tests.test_core.test_views.conftest import (
	BaseViewTestClass,
	APIClientFactory,
)
import pytest
from django.utils import timezone
from urllib.parse import urlparse, parse_qs, ParseResult
from rest_framework.test import APIClient
from oidc_provider.models import Client, UserConsent
from core.views.mixins.application import ApplicationViewMixin
from core.models.user import User
from interlock_backend.settings import (
	OIDC_INTERLOCK_LOGIN_COOKIE,
	OIDC_SKIP_CONSENT_EXPIRE,
)
from rest_framework.response import Response
from rest_framework import status

# Constants from your code
from core.constants.oidc import (
	QK_ERROR,
	QK_ERROR_DETAIL,
	OIDC_PROMPT_CONSENT,
	OIDC_PROMPT_LOGIN,
	OIDC_COOKIE_VUE_REDIRECT,
	OIDC_COOKIE_VUE_ABORT,
	OIDC_COOKIE_VUE_LOGIN,
)
from core.models.application import ApplicationSecurityGroup
from interlock_backend.settings import LOGIN_URL
from tests.test_core.conftest import (
	RuntimeSettingsFactory,
	ConnectorFactory,
	LDAPEntryFactoryProtocol,
	LDAPConnectorMock,
)
from core.views.oidc import OidcAuthorizeView
from typing import Protocol
from core.constants.attrs import (
	LOCAL_ATTR_ID,
	LDAP_ATTR_DN,
	LDAP_ATTR_GROUP_MEMBERS,
	LDAP_ATTR_OBJECT_CLASS,
)


@pytest.fixture
def f_ldap_group(
	fc_ldap_entry: LDAPEntryFactoryProtocol,
	f_user_ldap: User,
):
	return fc_ldap_entry(
		spec=False,
		**{
			LDAP_ATTR_DN: "mock_group_dn",
			LDAP_ATTR_GROUP_MEMBERS: [f_user_ldap.distinguished_name],
			LDAP_ATTR_OBJECT_CLASS: ["top", "group"],
		},
	)


@pytest.fixture(autouse=True)
def f_ldap_connector(g_ldap_connector: ConnectorFactory, f_ldap_group):
	m_connector = g_ldap_connector(
		patch_path="core.views.mixins.oidc.LDAPConnector"
	)
	m_connector.connection.entries = []
	return m_connector


@pytest.fixture(autouse=True)
def add_all_response_types(f_client: Client):
	response_types = ApplicationViewMixin.get_response_type_id_map()
	for rt_id in response_types.values():
		f_client.response_types.add(rt_id)


class UserConsentFactory(Protocol):
	def __call__(self, user: User, client: Client) -> UserConsent: ...


@pytest.fixture
def fc_user_consent(db) -> UserConsentFactory:
	def maker(user: User, client: Client):
		return UserConsent.objects.create(
			user=user,
			client=client,
			date_given=timezone.now(),
			expires_at=timezone.now() + OIDC_SKIP_CONSENT_EXPIRE,
			scope=client.scope,
		)

	return maker


@pytest.fixture
def user_consent(
	fc_user_consent: UserConsentFactory,
	admin_user: User,
	f_client: Client,
):
	return fc_user_consent(user=admin_user, client=f_client)


@pytest.fixture
def f_runtime_settings(g_runtime_settings: RuntimeSettingsFactory):
	return g_runtime_settings()


class TestCustomOidcViewSet(BaseViewTestClass):
	_endpoint = "oidc-consent"

	def test_consent_success_new_consent(
		self,
		admin_user: User,
		admin_user_client: APIClient,
		f_client: Client,
	):
		data = {
			"client_id": f_client.client_id,
			"next": f_client.redirect_uris[0],
		}
		response: Response = admin_user_client.post(
			self.endpoint,
			data=data,
			format="json",
		)

		assert response.status_code == status.HTTP_200_OK
		assert response.data["code"] == 0
		assert response.data["data"]["redirect_uri"] == data["next"]
		assert UserConsent.objects.filter(user=admin_user).exists()

	def test_consent_success_existing_consent(
		self,
		admin_user_client: APIClient,
		user_consent: UserConsent,
	):
		data = {
			"client_id": user_consent.client.client_id,
			"next": user_consent.client.redirect_uris[0],
		}
		old_expiry = user_consent.expires_at

		response: Response = admin_user_client.post(
			self.endpoint, data=data, format="json"
		)

		user_consent.refresh_from_db()
		assert response.status_code == status.HTTP_200_OK
		assert user_consent.expires_at > old_expiry

	def test_consent_missing_next(
		self,
		admin_user_client: APIClient,
		f_client: Client,
	):
		data = {"client_id": f_client.client_id}
		response: Response = admin_user_client.post(
			self.endpoint, data=data, format="json"
		)

		assert response.status_code == status.HTTP_302_FOUND
		assert QK_ERROR in response.url
		assert "oidc_no_next_uri" in response.url

	def test_consent_invalid_client(
		self,
		f_client: Client,
		admin_user_client: APIClient,
	):
		data = {
			"client_id": "invalid-client",
			"next": f_client.redirect_uris[0],
		}
		response: Response = admin_user_client.post(
			self.endpoint, data=data, format="json"
		)

		assert response.status_code == status.HTTP_302_FOUND
		assert QK_ERROR in response.url
		assert "oidc_no_client" in response.url

	def test_consent_get_exception(
		self,
		mocker: MockerFixture,
		f_client: Client,
		admin_user_client: APIClient,
	):
		mocker.patch.object(
			UserConsent.objects,
			"get",
			side_effect=Exception("Some Random Exception"),
		)
		data = {
			"client_id": f_client.client_id,
			"next": f_client.redirect_uris[0],
		}
		response: Response = admin_user_client.post(
			self.endpoint, data=data, format="json"
		)

		assert response.status_code == status.HTTP_302_FOUND
		assert QK_ERROR in response.url
		assert "oidc_consent_get" in response.url


class TestOidcAuthorizeView(BaseViewTestClass):
	_endpoint = "oidc-authorize"

	def test_get_unauthorized_initial_redirect(
		self,
		f_client: Client,
	):
		anon_client = APIClient()
		params = {
			"response_type": "code",
			"client_id": f_client.client_id,
			"redirect_uri": f_client.redirect_uris[0],
			"scope": "openid profile email",
			"state": "teststate123",
			"nonce": "testnonce123",
			"code_challenge": "testchallenge123",
			"code_challenge_method": "S256",
		}
		response: Response = anon_client.get(self.endpoint, params)

		assert response.status_code == status.HTTP_302_FOUND
		parsed_url: ParseResult = urlparse(response.url)
		parsed_qs = parse_qs(parsed_url.query)
		assert not QK_ERROR in parsed_qs
		assert response.url.startswith(LOGIN_URL)
		expected_params = {
			p: v for p, v in params.items() if p not in ("state",)
		}
		for p, v in expected_params.items():
			if " " in v:
				assert parsed_qs[p][0] == v.replace(" ", "+")
			else:
				assert parsed_qs[p][0] == v

	def test_invalid_params_raises(
		self,
		mocker: MockerFixture,
		admin_user: User,
		admin_user_client: APIClient,
		f_client: Client,
		user_consent: UserConsent,
	):
		m_user_requires_consent = mocker.patch.object(
			OidcAuthorizeView,
			"user_requires_consent",
			return_value=False,
		)
		m_user_can_access_app = mocker.patch.object(
			OidcAuthorizeView,
			"user_can_access_app",
			return_value=True,
		)
		params = {
			"response_type": "bad_response_type",
			"client_id": f_client.client_id,
			"redirect_uri": f_client.redirect_uris[0],
			"scope": "openid profile email",
			"nonce": "testnonce123",
		}

		admin_user_client.cookies[OIDC_INTERLOCK_LOGIN_COOKIE] = (
			OIDC_COOKIE_VUE_REDIRECT
		)
		response: Response = admin_user_client.get(
			self.endpoint,
			data=params,
		)

		assert response.status_code == status.HTTP_302_FOUND
		m_user_requires_consent.assert_not_called()
		m_user_can_access_app.assert_not_called()
		parsed_url: ParseResult = urlparse(response.url)
		parsed_qs = parse_qs(parsed_url.query)
		assert parsed_qs[QK_ERROR][0] == "true"
		assert (
			int(parsed_qs[QK_ERROR_DETAIL][0]) == status.HTTP_406_NOT_ACCEPTABLE
		)

	def test_get_successful_authorization_mocked(
		self,
		mocker: MockerFixture,
		admin_user: User,
		admin_user_client: APIClient,
		f_client: Client,
		user_consent: UserConsent,
	):
		m_user_requires_consent = mocker.patch.object(
			OidcAuthorizeView,
			"user_requires_consent",
			return_value=False,
		)
		m_user_can_access_app = mocker.patch.object(
			OidcAuthorizeView,
			"user_can_access_app",
			return_value=True,
		)
		params = {
			"response_type": "code",
			"client_id": f_client.client_id,
			"redirect_uri": f_client.redirect_uris[0],
			"scope": "openid profile email",
			"state": "teststate123",
			"nonce": "testnonce123",
			"code_challenge": "testchallenge123",
			"code_challenge_method": "S256",
		}
		# Set up session and cookies
		session = admin_user_client.session
		session["_oidc_authn_params"] = params
		session["oidc_authn_params_state"] = params["state"]
		session.save()

		admin_user_client.cookies[OIDC_INTERLOCK_LOGIN_COOKIE] = (
			OIDC_COOKIE_VUE_REDIRECT
		)
		response: Response = admin_user_client.get(
			self.endpoint,
			data=params,
		)

		assert response.status_code == status.HTTP_302_FOUND
		m_user_requires_consent.assert_called_once_with(user=admin_user)
		m_user_can_access_app.assert_called_once_with(user=admin_user)
		parsed_url: ParseResult = urlparse(response.url)
		parsed_qs = parse_qs(parsed_url.query)
		expected_params = {
			"code",
			"state",
		}
		for p in expected_params:
			assert p in parsed_qs

	@pytest.mark.parametrize(
		"user_fixture",
		(
			"admin_user",
			"f_user_local",
			"f_user_ldap",
		),
	)
	def test_get_successful_authorization(
		self,
		mocker: MockerFixture,
		request: FixtureRequest,
		g_interlock_ldap_enabled,
		user_fixture: str,
		f_api_client: APIClientFactory,
		f_client: Client,
		f_application_group: ApplicationSecurityGroup,
		fc_user_consent: UserConsentFactory,
		f_ldap_connector: LDAPConnectorMock,
		f_ldap_group,
	):
		m_user: User = request.getfixturevalue(user_fixture)
		api_client = f_api_client(user=m_user)
		user_consent = fc_user_consent(user=m_user, client=f_client)
		f_ldap_connector.connection.entries = [f_ldap_group]

		if m_user.id not in f_application_group.users.values_list(
			LOCAL_ATTR_ID, flat=True
		):
			f_application_group.users.add(m_user)
			f_application_group.save()

		params = {
			"response_type": "code",
			"client_id": f_client.client_id,
			"redirect_uri": f_client.redirect_uris[0],
			"scope": "openid profile email",
			"state": "teststate123",
			"nonce": "testnonce123",
			"code_challenge": "testchallenge123",
			"code_challenge_method": "S256",
		}
		# Set up session and cookies
		session = api_client.session
		session["_oidc_authn_params"] = params
		session["oidc_authn_params_state"] = params["state"]
		session.save()

		api_client.cookies[OIDC_INTERLOCK_LOGIN_COOKIE] = (
			OIDC_COOKIE_VUE_REDIRECT
		)
		response: Response = api_client.get(
			self.endpoint,
			data=params,
		)

		assert response.status_code == status.HTTP_302_FOUND
		parsed_url: ParseResult = urlparse(response.url)
		parsed_qs = parse_qs(parsed_url.query)
		expected_params = {
			"code",
			"state",
		}
		assert set(parsed_qs.keys()) == expected_params
		for p in expected_params:
			assert p in parsed_qs

	@pytest.mark.parametrize(
		"user_fixture",
		(
			"admin_user",
			"f_user_local",
			"f_user_ldap",
		),
	)
	def test_get_unsuccessful_authorization(
		self,
		mocker: MockerFixture,
		request: FixtureRequest,
		g_interlock_ldap_enabled,
		user_fixture: str,
		f_api_client: APIClientFactory,
		f_client: Client,
		f_application_group: ApplicationSecurityGroup,
		fc_user_consent: UserConsentFactory,
	):
		m_user: User = request.getfixturevalue(user_fixture)
		api_client = f_api_client(user=m_user)
		user_consent = fc_user_consent(user=m_user, client=f_client)

		app_group_modified = False
		if m_user.id in f_application_group.users.values_list(
			LOCAL_ATTR_ID, flat=True
		):
			f_application_group.users.remove(m_user)
			app_group_modified = True
		if (
			m_user.distinguished_name
			and m_user.distinguished_name in f_application_group.ldap_objects
		):
			f_application_group.ldap_objects.remove(m_user.distinguished_name)
			app_group_modified = True
		if app_group_modified:
			f_application_group.save()

		params = {
			"response_type": "code",
			"client_id": f_client.client_id,
			"redirect_uri": f_client.redirect_uris[0],
			"scope": "openid profile email",
			"state": "teststate123",
			"nonce": "testnonce123",
			"code_challenge": "testchallenge123",
			"code_challenge_method": "S256",
		}
		# Set up session and cookies
		session = api_client.session
		session["_oidc_authn_params"] = params
		session["oidc_authn_params_state"] = params["state"]
		session.save()

		api_client.cookies[OIDC_INTERLOCK_LOGIN_COOKIE] = (
			OIDC_COOKIE_VUE_REDIRECT
		)
		response: Response = api_client.get(
			self.endpoint,
			data=params,
		)

		assert response.status_code == status.HTTP_302_FOUND
		parsed_url: ParseResult = urlparse(response.url)
		parsed_qs = parse_qs(parsed_url.query)
		assert parsed_qs[QK_ERROR][0] == "true"
		assert int(parsed_qs[QK_ERROR_DETAIL][0]) == status.HTTP_403_FORBIDDEN

	def test_get_invalid_prompt(
		self,
		admin_user_client: APIClient,
		f_client: Client,
	):
		response: Response = admin_user_client.get(
			self.endpoint,
			{
				"client_id": f_client.client_id,
				"response_type": "code",
				"scope": "openid",
				"redirect_uri": f_client.redirect_uris[0],
				"prompt": "invalid_prompt",
			},
		)

		assert response.status_code == status.HTTP_302_FOUND
		parsed_url: ParseResult = urlparse(response.url)
		parsed_qs = parse_qs(parsed_url.query)
		assert parsed_qs[QK_ERROR][0] == "true"
		assert parsed_qs[QK_ERROR_DETAIL][0] == "oidc_prompt_unsupported"

	def test_get_abort_cookie(
		self,
		admin_user_client: APIClient,
		f_client: Client,
	):
		admin_user_client.cookies[OIDC_INTERLOCK_LOGIN_COOKIE] = (
			OIDC_COOKIE_VUE_ABORT
		)
		response: Response = admin_user_client.get(
			self.endpoint,
			{
				"client_id": f_client.client_id,
				"response_type": "code",
				"scope": "openid",
				"redirect_uri": f_client.redirect_uris[0],
				"prompt": OIDC_PROMPT_LOGIN,
			},
		)

		assert response.status_code == status.HTTP_302_FOUND
		parsed_url: ParseResult = urlparse(response.url)
		parsed_qs = parse_qs(parsed_url.query)
		assert parsed_qs[QK_ERROR][0] == "true"
		assert not response.cookies[OIDC_INTERLOCK_LOGIN_COOKIE].value

	def test_get_require_consent(
		self,
		admin_user_client: APIClient,
		f_client: Client,
	):
		admin_user_client.cookies[OIDC_INTERLOCK_LOGIN_COOKIE] = (
			OIDC_COOKIE_VUE_REDIRECT
		)
		response: Response = admin_user_client.get(
			self.endpoint,
			{
				"client_id": f_client.client_id,
				"response_type": "code",
				"scope": "openid",
				"redirect_uri": f_client.redirect_uris[0],
				"prompt": OIDC_PROMPT_CONSENT,
			},
		)

		assert response.status_code == status.HTTP_302_FOUND
		assert (
			response.cookies[OIDC_INTERLOCK_LOGIN_COOKIE].value
			== OIDC_COOKIE_VUE_LOGIN
		)
		assert LOGIN_URL in response.url

	def test_get_invalid_cookie_value(
		self,
		admin_user_client: APIClient,
		f_client: Client,
	):
		admin_user_client.cookies[OIDC_INTERLOCK_LOGIN_COOKIE] = "invalid_value"
		response: Response = admin_user_client.get(
			self.endpoint,
			{
				"client_id": f_client.client_id,
				"response_type": "code",
				"scope": "openid",
				"redirect_uri": f_client.redirect_uris[0],
			},
		)

		assert response.status_code == status.HTTP_302_FOUND
		parsed_url: ParseResult = urlparse(response.url)
		parsed_qs = parse_qs(parsed_url.query)
		assert parsed_qs[QK_ERROR][0] == "true"
		assert int(parsed_qs[QK_ERROR_DETAIL][0]) == status.HTTP_400_BAD_REQUEST
