# tests.test_core.test_views.conftest
########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest

################################################################################
from rest_framework.test import APIClient
from core.ldap.defaults import LDAP_DOMAIN

# Models
from core.models.user import User, USER_TYPE_LDAP, USER_TYPE_LOCAL
from core.models.application import Application, ApplicationSecurityGroup
from oidc_provider.models import Client

# Other
from rest_framework_simplejwt.tokens import RefreshToken
from typing import Protocol
from http import HTTPMethod
from interlock_backend.test_settings import SIMPLE_JWT
from django.urls import reverse, get_resolver, get_urlconf

_ACCESS_NAME = SIMPLE_JWT["AUTH_COOKIE_NAME"]
_REFRESH_NAME = SIMPLE_JWT["REFRESH_COOKIE_NAME"]
_JWT_SAMESITE = SIMPLE_JWT["AUTH_COOKIE_SAME_SITE"]
_JWT_SECURE = SIMPLE_JWT["AUTH_COOKIE_SECURE"]


@pytest.fixture(
	params=[
		# LDAP Domain
		("/api/ldap/domain/", HTTPMethod.GET),  # Retrieve Main Domain Details
		("/api/ldap/domain/zone/", HTTPMethod.POST),  # Retrieve Specific Zone
		("/api/ldap/domain/", HTTPMethod.POST),  # Create
		("/api/ldap/domain/", HTTPMethod.PATCH),  # Delete
		# LDAP Record
		("/api/ldap/record/", HTTPMethod.POST),  # Create
		("/api/ldap/record/", HTTPMethod.PUT),  # Update
		("/api/ldap/record/", HTTPMethod.PATCH),  # Delete
		# LDAP Groups
		("/api/ldap/groups/", HTTPMethod.GET),
		("/api/ldap/groups/retrieve-dn/", HTTPMethod.POST),  # Retrieve
		("/api/ldap/groups/", HTTPMethod.POST),  # Create
		("/api/ldap/groups/", HTTPMethod.PUT),  # Update
		("/api/ldap/groups/", HTTPMethod.PATCH),  # Destroy
		# LDAP Users
		("/api/ldap/users/", HTTPMethod.GET),
		("/api/ldap/users/retrieve/", HTTPMethod.POST),
		("/api/ldap/users/", HTTPMethod.POST),  # Create
		("/api/ldap/users/", HTTPMethod.PUT),  # Update
		("/api/ldap/users/", HTTPMethod.PATCH),  # Destroy
		("/api/ldap/users/change-status/", HTTPMethod.POST),
		("/api/ldap/users/change-password/", HTTPMethod.POST),
		("/api/ldap/users/unlock/", HTTPMethod.POST),
		("/api/ldap/users/bulk/export/", HTTPMethod.GET),
		("/api/ldap/users/bulk/create/", HTTPMethod.POST),
		("/api/ldap/users/bulk/update/", HTTPMethod.POST),
		("/api/ldap/users/bulk/destroy/", HTTPMethod.POST),
		("/api/ldap/users/bulk/change-status/", HTTPMethod.POST),
		("/api/ldap/users/bulk/unlock/", HTTPMethod.POST),
		("/api/ldap/users/self/change-password/", HTTPMethod.POST),
		("/api/ldap/users/self/update/", HTTPMethod.POST),
		("/api/ldap/users/self/info/", HTTPMethod.GET),
		("/api/ldap/users/self/fetch/", HTTPMethod.GET),
		# LDAP Directory Tree and OUs
		("/api/ldap/dirtree/", HTTPMethod.GET),  # Retrieve Dirtree
		("/api/ldap/dirtree/", HTTPMethod.POST),  # Create
		("/api/ldap/dirtree/", HTTPMethod.PATCH),  # Destroy
		("/api/ldap/dirtree/rename/", HTTPMethod.POST),
		("/api/ldap/dirtree/move/", HTTPMethod.POST),
		("/api/ldap/dirtree/organizational-units/", HTTPMethod.GET),
		# Application Groups
		("/api/application/group/create-info/", HTTPMethod.GET),
		("/api/application/group/", HTTPMethod.GET),  # List
		("/api/application/group/", HTTPMethod.POST),  # Create
		("/api/application/group/{pk}/", HTTPMethod.GET),  # Retrieve
		("/api/application/group/{pk}/", HTTPMethod.PUT),  # Update
		("/api/application/group/{pk}/", HTTPMethod.DELETE),  # Delete
		("/api/application/group/{pk}/change-status/", HTTPMethod.PATCH),
		# Application
		("/api/application/", HTTPMethod.GET),  # List
		("/api/application/", HTTPMethod.POST),  # Create
		("/api/application/{pk}/", HTTPMethod.GET),  # Retrieve
		("/api/application/{pk}/", HTTPMethod.DELETE),  # Delete
		("/api/application/{pk}/", HTTPMethod.PUT),  # Update
		# Local User
		("/api/users/", HTTPMethod.GET),  # List
		("/api/users/", HTTPMethod.POST),  # Create
		("/api/users/{pk}/", HTTPMethod.GET),  # Retrieve
		("/api/users/{pk}/", HTTPMethod.PUT),  # Update
		("/api/users/{pk}/", HTTPMethod.DELETE),  # Delete
		("/api/users/{pk}/change-status/", HTTPMethod.POST),
		("/api/users/{pk}/change-password/", HTTPMethod.POST),
		("/api/users/bulk/export/", HTTPMethod.GET),
		("/api/users/self/update/", HTTPMethod.POST),
		("/api/users/self/change-password/", HTTPMethod.POST),
		# Logs
		("/api/logs/", HTTPMethod.GET),
		("/api/logs/reset/", HTTPMethod.GET),
		("/api/logs/truncate/", HTTPMethod.POST),
		# Settings
		("/api/settings/", HTTPMethod.GET),  # List
		("/api/settings/", HTTPMethod.POST),  # Create
		("/api/settings/{pk}/", HTTPMethod.GET),  # Retrieve
		("/api/settings/{pk}/", HTTPMethod.DELETE),  # Delete
		("/api/settings/{pk}/enable/", HTTPMethod.POST),
		("/api/settings/{pk}/rename/", HTTPMethod.POST),
		("/api/settings/save/", HTTPMethod.POST),  # Update
		("/api/settings/reset/", HTTPMethod.GET),
		("/api/settings/test/", HTTPMethod.POST),
		("/api/settings/sync-users/", HTTPMethod.GET),
		("/api/settings/prune-users/", HTTPMethod.GET),
		("/api/settings/purge-users/", HTTPMethod.GET),
		# Token
		# TOTP
		("/api/totp/", HTTPMethod.GET),
		("/api/totp/create-device/", HTTPMethod.GET),
		("/api/totp/create-device/", HTTPMethod.POST),
		("/api/totp/validate-device/", HTTPMethod.POST),
		("/api/totp/validate-device/", HTTPMethod.PUT),
		("/api/totp/delete-device/", HTTPMethod.POST),
		("/api/totp/delete-device/", HTTPMethod.DELETE),
		("/api/totp/delete-for-user/", HTTPMethod.POST),
		("/api/totp/delete-for-user/", HTTPMethod.DELETE),
		# OIDC
		("/openid/consent", HTTPMethod.POST),
	],
	ids=lambda x: f"{x[1]}: {x[0]}",
	scope="session",
)
def g_all_endpoints(request: FixtureRequest):
	"""Returns tuple of (endpoint, method)"""
	return request.param


# Filtered fixture - only LDAP domain endpoints
ldap_endpoints = (
	# LDAP Domain
	("/api/ldap/domain/zone/", HTTPMethod.POST),  # Retrieve Specific Zone
	("/api/ldap/domain/", HTTPMethod.POST),  # Create
	("/api/ldap/domain/", HTTPMethod.PATCH),  # Delete
	# LDAP Record
	("/api/ldap/record/", HTTPMethod.POST),  # Create
	("/api/ldap/record/", HTTPMethod.PUT),  # Update
	("/api/ldap/record/", HTTPMethod.PATCH),  # Delete
	# LDAP Groups
	("/api/ldap/groups/", HTTPMethod.GET),
	("/api/ldap/groups/retrieve-dn/", HTTPMethod.POST),  # Retrieve
	("/api/ldap/groups/", HTTPMethod.POST),  # Create
	("/api/ldap/groups/", HTTPMethod.PUT),  # Update
	("/api/ldap/groups/", HTTPMethod.PATCH),  # Destroy
	# LDAP Users
	("/api/ldap/users/", HTTPMethod.GET),
	("/api/ldap/users/retrieve/", HTTPMethod.POST),
	("/api/ldap/users/", HTTPMethod.POST),  # Create
	("/api/ldap/users/", HTTPMethod.PUT),  # Update
	("/api/ldap/users/", HTTPMethod.PATCH),  # Destroy
	("/api/ldap/users/change-status/", HTTPMethod.POST),
	("/api/ldap/users/change-password/", HTTPMethod.POST),
	("/api/ldap/users/unlock/", HTTPMethod.POST),
	("/api/ldap/users/bulk/export/", HTTPMethod.GET),
	("/api/ldap/users/bulk/create/", HTTPMethod.POST),
	("/api/ldap/users/bulk/update/", HTTPMethod.POST),
	("/api/ldap/users/bulk/destroy/", HTTPMethod.POST),
	("/api/ldap/users/bulk/change-status/", HTTPMethod.POST),
	("/api/ldap/users/bulk/unlock/", HTTPMethod.POST),
	("/api/ldap/users/self/change-password/", HTTPMethod.POST),
	("/api/ldap/users/self/update/", HTTPMethod.POST),
	("/api/ldap/users/self/fetch/", HTTPMethod.GET),
	# LDAP Directory Tree and OUs
	("/api/ldap/dirtree/", HTTPMethod.GET),  # Retrieve Dirtree
	("/api/ldap/dirtree/", HTTPMethod.POST),  # Create
	("/api/ldap/dirtree/", HTTPMethod.PATCH),  # Destroy
	("/api/ldap/dirtree/rename/", HTTPMethod.POST),
	("/api/ldap/dirtree/move/", HTTPMethod.POST),
	("/api/ldap/dirtree/organizational-units/", HTTPMethod.GET),
)


@pytest.fixture(
	params=[
		# Access underlying params
		p
		for p in g_all_endpoints._pytestfixturefunction.params
		# Filter condition
		if p in ldap_endpoints
	],
	ids=lambda x: f"{x[1].upper()}: {x[0]} (LDAP Required)",
	scope="session",
)
def g_ldap_domain_endpoints(request: FixtureRequest):
	return request.param


# Filtered fixture - only LDAP domain endpoints
excluded_from_auth_required = ("/api/ldap/domain/details/",)


@pytest.fixture(
	params=[
		# Access underlying params
		p
		for p in g_all_endpoints._pytestfixturefunction.params
		# Filter condition
		if p[0] not in excluded_from_auth_required
	],
	ids=lambda x: f"{x[1].upper()}: {x[0]} (Auth. Required)",
	scope="session",
)
def g_authenticated_endpoints(request: FixtureRequest):
	return request.param


excluded_from_admin_only = (
	("/api/ldap/domain/", HTTPMethod.GET),  # Create
	("/api/ldap/users/self/change-password/", HTTPMethod.POST),
	("/api/ldap/users/self/update/", HTTPMethod.POST),
	("/api/ldap/users/self/fetch/", HTTPMethod.GET),
	("/api/ldap/users/self/info/", HTTPMethod.GET),
	("/api/users/self/update/", HTTPMethod.POST),
	("/api/users/self/change-password/", HTTPMethod.POST),
	("/api/totp/", HTTPMethod.GET),
	("/api/totp/create-device/", HTTPMethod.GET),
	("/api/totp/create-device/", HTTPMethod.POST),
	("/api/totp/validate-device/", HTTPMethod.POST),
	("/api/totp/validate-device/", HTTPMethod.PUT),
	("/api/totp/delete-device/", HTTPMethod.POST),
	("/api/totp/delete-device/", HTTPMethod.DELETE),
	("/api/totp/delete-for-user/", HTTPMethod.POST),
	("/api/totp/delete-for-user/", HTTPMethod.DELETE),
	("/openid/consent", HTTPMethod.POST),
)


@pytest.fixture(
	params=[
		# Access underlying params
		p
		for p in g_all_endpoints._pytestfixturefunction.params
		# Filter condition
		if p not in excluded_from_admin_only
	],
	ids=lambda x: f"{x[1].upper()}: {x[0]} (Admin Required)",
	scope="session",
)
def g_admin_endpoints(request: FixtureRequest):
	return request.param


@pytest.fixture
def api_client():
	"""Unauthenticated API client"""
	return APIClient()


class UserFactory(Protocol):
	def __call__(
		self,
		username="testuser",
		email=f"test@{LDAP_DOMAIN}",
		password="somepassword",
		is_staff=False,
		is_superuser=False,
		**kwargs,
	) -> User: ...


@pytest.fixture
def user_factory(db) -> UserFactory:
	"""Factory to create test users with db access"""

	def create_user(
		username="testuser",
		email=f"test@{LDAP_DOMAIN}",
		password="somepassword",
		is_staff=False,
		is_superuser=False,
		**kwargs,
	):
		user = User.objects.create_user(
			username=username,
			email=email,
			password=password,
			is_staff=is_staff,
			is_superuser=is_superuser,
			**kwargs,
		)
		user.raw_password = password  # Store password for testing
		return user

	return create_user


@pytest.fixture
def disabled_user(user_factory):
	"""Regular user instance without admin privileges"""
	return user_factory(is_enabled=False)


@pytest.fixture
def normal_user(user_factory):
	"""Regular user instance without admin privileges"""
	return user_factory()


@pytest.fixture
def admin_user(user_factory):
	"""Admin user instance"""
	return user_factory(is_staff=True, is_superuser=True)


class APIClientFactory(Protocol):
	def __call__(
		self,
		user: User,
		use_endpoint: bool = True,
		refresh_token: RefreshToken = None,
	) -> APIClient: ...


@pytest.fixture
def f_api_client(api_client: APIClient):
	def maker(user: User, **kwargs):
		refresh = kwargs.pop("refresh_token", None)
		if not refresh and kwargs.pop("use_endpoint", True):
			api_client.post(
				"/api/token/",
				data={
					"username": user.username,
					"password": user.raw_password,
				},
			)
		else:
			if not refresh:
				refresh = RefreshToken.for_user(user)

			api_client.cookies[_ACCESS_NAME] = str(refresh.access_token)
			api_client.cookies[_REFRESH_NAME] = str(refresh)
			for cookie in (_ACCESS_NAME, _REFRESH_NAME):
				api_client.cookies[cookie]["httponly"] = True
				api_client.cookies[cookie]["samesite"] = _JWT_SAMESITE
				api_client.cookies[cookie]["secure"] = _JWT_SECURE
		return api_client

	return maker


@pytest.fixture
def disabled_user_client(
	disabled_user: User, f_api_client: APIClientFactory
) -> APIClient:
	"""Authenticated API client for disabled user"""
	return f_api_client(user=disabled_user)


@pytest.fixture
def normal_user_client(
	normal_user: User, f_api_client: APIClientFactory
) -> APIClient:
	return f_api_client(user=normal_user)


@pytest.fixture
def admin_user_client(
	admin_user: User, f_api_client: APIClientFactory
) -> APIClient:
	return f_api_client(user=admin_user)


MOCK_PASSWORD = "mock_password"


@pytest.fixture
def f_user_local(user_factory: UserFactory):
	"""Test creating a user with all fields"""
	return user_factory(
		username="testuserlocal",
		password=MOCK_PASSWORD,
		email="testuserlocal@example.org",
		user_type=USER_TYPE_LOCAL,
		is_enabled=True,
	)


@pytest.fixture
def f_user_ldap(user_factory: UserFactory):
	"""Test creating a user with all fields"""
	return user_factory(
		username="testuserldap",
		password=MOCK_PASSWORD,
		email="testuserldap@example.org",
		distinguished_name="cn=john,ou=users,dc=example,dc=com",
		user_type=USER_TYPE_LDAP,
		is_enabled=True,
	)


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
def f_application_group(
	f_application: Application,
	f_user_local: User,
	f_user_ldap: User,
):
	"""Fixture creating a test application group in the database"""
	m_asg = ApplicationSecurityGroup(
		application=f_application,
		ldap_objects=["some_group_dn"],
		enabled=True,
	)
	m_asg.save()
	m_asg.users.add(f_user_local)
	m_asg.ldap_objects.append(f_user_ldap.distinguished_name)
	m_asg.save()
	return m_asg


@pytest.fixture
def f_client(f_application: Application) -> Client:
	m_client = Client.objects.create(
		client_id=f_application.client_id,
		redirect_uris=f_application.redirect_uris.split(","),
		require_consent=True,
		reuse_consent=True,
	)
	return m_client


class BaseViewTestClass:
	_endpoint = None

	@property
	def endpoint(self):
		if not self._endpoint:
			raise NotImplementedError("Test class requires an endpoint")
		# For debugging
		urlconf = get_urlconf()
		resolver = get_resolver(urlconf)  # noqa: F841
		#
		return reverse(self._endpoint)


class BaseViewTestClassWithPk:
	_endpoint = None
	_pk = None

	@property
	def endpoint(self):
		if not self._endpoint:
			raise NotImplementedError("Test class requires an endpoint")
		if not self._pk:
			raise NotImplementedError(
				"Test class requires a primary key for reverse url fetching"
			)
		return reverse(self._endpoint, args=(self._pk,))
