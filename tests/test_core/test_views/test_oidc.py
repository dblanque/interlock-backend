########################### Standard Pytest Imports ############################
import pytest
################################################################################
from tests.test_core.test_views.conftest import BaseViewTestClass
import pytest
from django.utils import timezone
from urllib.parse import urlparse, parse_qs, ParseResult
from rest_framework.test import APIClient
from oidc_provider.models import Client, UserConsent, ResponseType
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
	OIDC_PROMPT_CONSENT,
	OIDC_PROMPT_LOGIN,
	OIDC_COOKIE_VUE_REDIRECT,
	OIDC_COOKIE_VUE_ABORT
)
from interlock_backend.settings import LOGIN_URL
from tests.test_core.conftest import RuntimeSettingsFactory

@pytest.fixture
def f_redirect_uri():
	return 'https://example.com/callback'

@pytest.fixture
def oidc_client(db, f_application, f_redirect_uri: str):
	m_client = Client(
		client_id='test-client',
		name='Test Client',
		scope=['openid', 'profile', 'email']
	)
	rt = ResponseType.objects.all()
	m_client.redirect_uris = [f_redirect_uri]
	m_client.save()
	m_client.response_types.add(ResponseType.objects.get(value="code"))
	m_client.save()
	return m_client

@pytest.fixture
def user_consent(db, admin_user: User, oidc_client: Client):
	return UserConsent.objects.create(
		user=admin_user,
		client=oidc_client,
		date_given=timezone.now(),
		expires_at=timezone.now() + OIDC_SKIP_CONSENT_EXPIRE,
		scope=oidc_client.scope
	)

@pytest.fixture
def f_runtime_settings(g_runtime_settings: RuntimeSettingsFactory):
	return g_runtime_settings()

class TestCustomOidcViewSet(BaseViewTestClass):
	_endpoint = 'oidc-consent'

	def test_consent_success_new_consent(
		self,
		f_redirect_uri: str,
		admin_user: User,
		admin_user_client: APIClient,
		oidc_client: Client,
	):
		data = {
			'client_id': oidc_client.client_id,
			'next': f_redirect_uri
		}
		response: Response = admin_user_client.post(
			self.endpoint,
			data=data,
			format='json',
		)

		assert response.status_code == status.HTTP_200_OK
		assert response.data['code'] == 0
		assert response.data['data']['redirect_uri'] == data['next']
		assert UserConsent.objects.filter(user=admin_user).exists()

	def test_consent_success_existing_consent(
		self,
		f_redirect_uri: str,
		admin_user_client: APIClient,
		user_consent: UserConsent,
	):
		data = {
			'client_id': user_consent.client.client_id,
			'next': f_redirect_uri
		}
		old_expiry = user_consent.expires_at
		
		response: Response = admin_user_client.post(
			self.endpoint,
			data=data,
			format='json'
		)

		user_consent.refresh_from_db()
		assert response.status_code == status.HTTP_200_OK
		assert user_consent.expires_at > old_expiry

	def test_consent_missing_next(
		self,
		admin_user_client: APIClient,
		oidc_client: Client
	):
		data = {'client_id': oidc_client.client_id}
		response: Response = admin_user_client.post(
			self.endpoint,
			data=data,
			format='json'
		)

		assert response.status_code == status.HTTP_302_FOUND
		assert QK_ERROR in response.url
		assert 'oidc_no_next_uri' in response.url

	def test_consent_invalid_client(
		self,
		f_redirect_uri: str,
		admin_user_client: APIClient,
	):
		data = {
			'client_id': 'invalid-client',
			'next': f_redirect_uri
		}
		response: Response = admin_user_client.post(
			self.endpoint,
			data=data,
			format='json'
		)

		assert response.status_code == status.HTTP_302_FOUND
		assert QK_ERROR in response.url
		assert 'oidc_no_client' in response.url

class TestOidcAuthorizeView(BaseViewTestClass):
	_endpoint = "oidc-authorize"

	# Test cases
	# TODO
	# Success (Local or LDAP User Authenticates, no ASG)
	# Success (Local User Authenticates, is in ASG)
	# Success (LDAP User Authenticates, DN is in ASG)
	# Success (LDAP User Authenticates, is in LDAP Group within ASG)
	# Error (Local User Authenticates, not in ASG)
	# Error (LDAP User Authenticates, not in ASG or LDAP Group)
	def test_get_successful_authorization(
		self,
		admin_user_client: APIClient,
		oidc_client: Client,
	):
		params = {
			'response_type': 'code',
			'client_id': oidc_client.client_id,
			'redirect_uri': oidc_client.redirect_uris[0],
			'scope': 'openid profile email',
			'state': 'teststate123',
			'nonce': 'testnonce123',
			'code_challenge': 'testchallenge123',
			'code_challenge_method': 'S256',
		}
		# Set up session and cookies
		session = admin_user_client.session
		session['_oidc_authn_params'] = params
		session['oidc_authn_params_state'] = params['state']
		session.save()
		
		response: Response = admin_user_client.get(
			self.endpoint,
			data=params,
			HTTP_COOKIE=f'{OIDC_INTERLOCK_LOGIN_COOKIE}={OIDC_COOKIE_VUE_REDIRECT}'
		)

		assert response.status_code == 302
		parsed_url: ParseResult = urlparse(response.url)
		assert 'code' in parse_qs(parsed_url.query)

	def test_get_unauthenticated_redirect(
		self,
		f_redirect_uri: str,
		admin_user_client: APIClient,
		oidc_client: Client,
	):
		response: Response = admin_user_client.get(
			self.endpoint,
			{
				'client_id': oidc_client.client_id,
				'response_type': 'code',
				'scope': 'openid',
				'redirect_uri': f_redirect_uri,
				'prompt': OIDC_PROMPT_LOGIN
			},
			HTTP_COOKIE=f'{OIDC_INTERLOCK_LOGIN_COOKIE}={OIDC_COOKIE_VUE_REDIRECT}'
		)

		assert response.status_code == 302
		assert LOGIN_URL in response.url

	def test_get_invalid_prompt(
		self,
		f_redirect_uri: str,
		admin_user_client: APIClient,
		oidc_client: Client,
	):
		response: Response = admin_user_client.get(
			self.endpoint,
			{
				'client_id': oidc_client.client_id,
				'response_type': 'code',
				'scope': 'openid',
				'redirect_uri': f_redirect_uri,
				'prompt': 'invalid_prompt'
			}
		)

		assert response.status_code == 302
		assert QK_ERROR in response.url
		assert 'oidc_prompt_unsupported' in response.url

	def test_get_abort_cookie(
		self,
		f_redirect_uri: str,
		admin_user_client: APIClient,
		oidc_client: Client,
	):
		response: Response = admin_user_client.get(
			self.endpoint,
			{
				'client_id': oidc_client.client_id,
				'response_type': 'code',
				'scope': 'openid',
				'redirect_uri': f_redirect_uri,
				'prompt': OIDC_PROMPT_LOGIN
			},
			HTTP_COOKIE=f'{OIDC_INTERLOCK_LOGIN_COOKIE}={OIDC_COOKIE_VUE_ABORT}'
		)

		assert response.status_code == 302
		assert QK_ERROR in response.url
		assert OIDC_INTERLOCK_LOGIN_COOKIE not in response.cookies

	def test_get_require_consent(
		self,
		admin_user_client: APIClient,
		oidc_client: Client,
	):
		response: Response = admin_user_client.get(
			self.endpoint,
			{
				'client_id': oidc_client.client_id,
				'response_type': 'code',
				'scope': 'openid',
				'redirect_uri': f_redirect_uri,
				'prompt': OIDC_PROMPT_CONSENT
			},
			HTTP_COOKIE=f'{OIDC_INTERLOCK_LOGIN_COOKIE}={OIDC_COOKIE_VUE_REDIRECT}'
		)

		assert response.status_code == 302
		assert LOGIN_URL in response.url

	def test_get_invalid_cookie_value(
		self,
		f_redirect_uri: str,
		admin_user_client: APIClient,
		oidc_client: Client,
	):
		response: Response = admin_user_client.get(
			self.endpoint,
			{
				'client_id': oidc_client.client_id,
				'response_type': 'code',
				'scope': 'openid',
				'redirect_uri': f_redirect_uri
			},
			HTTP_COOKIE=f'{OIDC_INTERLOCK_LOGIN_COOKIE}=invalid_value'
		)

		assert response.status_code == 302
		assert QK_ERROR in response.url