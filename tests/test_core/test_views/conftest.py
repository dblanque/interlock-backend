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
from typing import Protocol
from rest_framework import status
from pytest import FixtureRequest
from interlock_backend.test_settings import SIMPLE_JWT
from typing import Protocol

_ACCESS_NAME = SIMPLE_JWT["AUTH_COOKIE_NAME"]
_REFRESH_NAME = SIMPLE_JWT["REFRESH_COOKIE_NAME"]
_JWT_SAMESITE=SIMPLE_JWT["AUTH_COOKIE_SAME_SITE"]
_JWT_SECURE=SIMPLE_JWT["AUTH_COOKIE_SECURE"]

@pytest.fixture(
	params=[
		# LDAP Domain
		("/api/ldap/domain/details/", "get"),
		("/api/ldap/domain/zones/", "post"),
		("/api/ldap/domain/insert/", "post"),
		("/api/ldap/domain/delete/", "post"),
		# LDAP Record
		("/api/ldap/record/insert/", "post"),
		("/api/ldap/record/update/", "put"),
		("/api/ldap/record/delete/", "post"),
	],
	ids=lambda x: f"{x[1].upper()}: {x[0]}",
)
def g_all_endpoints(request: FixtureRequest):
	"""Returns tuple of (endpoint, method)"""
	return request.param


# Filtered fixture - only LDAP domain endpoints
excluded_from_ldap = ("/api/ldap/domain/details/",)


@pytest.fixture(
	params=[
		# Access underlying params
		p
		for p in g_all_endpoints._pytestfixturefunction.params
		# Filter condition
		if p[0] not in excluded_from_ldap
	],
	ids=lambda x: f"{x[1].upper()}: {x[0]} (LDAP Required)",
)
def g_ldap_domain_endpoints(request: FixtureRequest):
	return request.param


# Filtered fixture - only LDAP domain endpoints
excluded_from_auth = ("/api/ldap/domain/details/",)


@pytest.fixture(
	params=[
		# Access underlying params
		p
		for p in g_all_endpoints._pytestfixturefunction.params
		# Filter condition
		if p[0] not in excluded_from_auth
	],
	ids=lambda x: f"{x[1].upper()}: {x[0]} (Auth. Required)",
)
def g_authenticated_endpoints(request: FixtureRequest):
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


class DisabledApiClient(Protocol):
	def __call__(self) -> APIClient: ...


@pytest.fixture
def disabled_user_client(
	disabled_user: User, api_client: APIClient
) -> DisabledApiClient:
	"""Authenticated API client for normal user"""
	api_client.post(
		"/api/token/",
		data={
			"username": disabled_user.username,
			"password": disabled_user.raw_password,
		},
	)
	# May use this later
	# refresh = RefreshToken.for_user(disabled_user)

	# api_client.cookies[_ACCESS_NAME] = str(refresh.access_token)
	# api_client.cookies[_REFRESH_NAME] = str(refresh)
	# for cookie in (_ACCESS_NAME, _REFRESH_NAME):
	# 	api_client.cookies[cookie]["httponly"] = True
	# 	api_client.cookies[cookie]["samesite"] = _JWT_SAMESITE
	# 	api_client.cookies[cookie]["secure"] = _JWT_SECURE
	return api_client


class NormalApiClient(Protocol):
	def __call__(self) -> APIClient: ...


@pytest.fixture
def normal_user_client(normal_user: User, api_client: APIClient) -> NormalApiClient:
	"""Authenticated API client for normal user"""
	api_client.post(
		"/api/token/",
		data={
			"username": normal_user.username,
			"password": normal_user.raw_password,
		},
	)
	# May use this later
	# refresh = RefreshToken.for_user(normal_user)

	# api_client.cookies[_ACCESS_NAME] = str(refresh.access_token)
	# api_client.cookies[_REFRESH_NAME] = str(refresh)
	# for cookie in (_ACCESS_NAME, _REFRESH_NAME):
	# 	api_client.cookies[cookie]["httponly"] = True
	# 	api_client.cookies[cookie]["samesite"] = _JWT_SAMESITE
	# 	api_client.cookies[cookie]["secure"] = _JWT_SECURE
	return api_client


class AdminApiClient(Protocol):
	def __call__(self) -> APIClient: ...


@pytest.fixture
def admin_user_client(admin_user: User, api_client: APIClient) -> AdminApiClient:
	"""Authenticated API client for admin user"""
	api_client.post(
		"/api/token/",
		data={
			"username": admin_user.username,
			"password": admin_user.raw_password,
		},
	)
	# May use this later
	# refresh = RefreshToken.for_user(admin_user)

	# api_client.cookies[_ACCESS_NAME] = str(refresh.access_token)
	# api_client.cookies[_REFRESH_NAME] = str(refresh)
	# for cookie in (_ACCESS_NAME, _REFRESH_NAME):
	# 	api_client.cookies[cookie]["httponly"] = True
	# 	api_client.cookies[cookie]["samesite"] = _JWT_SAMESITE
	# 	api_client.cookies[cookie]["secure"] = _JWT_SECURE
	return api_client

MOCK_PASSWORD = "mock_password"
@pytest.fixture
def f_user_local(user_factory: UserFactory):
	"""Test creating a user with all fields"""
	return user_factory(
		username="testuserlocal",
		password=MOCK_PASSWORD,
		email=f"testuserlocal@example.org",
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
def f_client(f_application) -> Client:
	m_client = Client.objects.create(
		client_id=f_application.client_id,
		redirect_uris=f_application.redirect_uris.split(","),
		require_consent=True,
		reuse_consent=True,
	)
	return m_client


@pytest.fixture
def f_endpoints_default_mock_result():
	return {
		"HomeViewSet": {
			"list": status.HTTP_200_OK,
		},
		"UserViewSet": {
			"list": status.HTTP_200_OK,
			"insert": status.HTTP_201_CREATED,
			"fetch": status.HTTP_200_OK,
			"update": status.HTTP_200_OK,
			"delete": status.HTTP_200_OK,
			"change_status": status.HTTP_200_OK,
			"change_password": status.HTTP_200_OK,
			"self_change_password": status.HTTP_200_OK,
			"self_update": status.HTTP_200_OK,
		},
		"LDAPUserViewSet": {
			"list": status.HTTP_200_OK,
			"fetch": status.HTTP_200_OK,
			"insert": status.HTTP_201_CREATED,
			"update": status.HTTP_200_OK,
			"delete": status.HTTP_200_OK,
			"unlock": status.HTTP_200_OK,
			"bulk_insert": status.HTTP_201_CREATED,
			"bulk_update": status.HTTP_200_OK,
			"bulk_delete": status.HTTP_200_OK,
			"bulk_unlock": status.HTTP_200_OK,
			"bulk_change_status": status.HTTP_200_OK,
			"change_status": status.HTTP_200_OK,
			"change_password": status.HTTP_200_OK,
			"self_change_password": status.HTTP_200_OK,
			"self_update": status.HTTP_200_OK,
			"self_fetch": status.HTTP_200_OK,
			"self_info": status.HTTP_200_OK,
		},
		"LDAPGroupsViewSet": {
			"list": status.HTTP_200_OK,
			"fetch": status.HTTP_200_OK,
			"insert": status.HTTP_201_CREATED,
			"update": status.HTTP_200_OK,
			"delete": status.HTTP_200_OK,
		},
		"LDAPDomainViewSet": {
			"details": status.HTTP_200_OK,
			"zones": status.HTTP_200_OK,
			"insert": status.HTTP_201_CREATED,
			"update": status.HTTP_200_OK,
			"delete": status.HTTP_200_OK,
		},
		"LDAPRecordViewSet": {
			"insert": status.HTTP_201_CREATED,
			"update": status.HTTP_200_OK,
			"delete": status.HTTP_200_OK,
		},
		"LDAPOrganizationalUnitViewSet": {
			"list": status.HTTP_200_OK,
			"dirtree": status.HTTP_200_OK,
			"move": status.HTTP_200_OK,
			"rename": status.HTTP_200_OK,
			"insert": status.HTTP_201_CREATED,
			"delete": status.HTTP_200_OK,
		},
		"SettingsViewSet": {
			"list": status.HTTP_200_OK,
			"fetch": status.HTTP_200_OK,
			"save": status.HTTP_200_OK,
			"reset": status.HTTP_200_OK,
			"test": status.HTTP_200_OK,
			"preset_create": status.HTTP_201_CREATED,
			"preset_delete": status.HTTP_200_OK,
			"preset_enable": status.HTTP_200_OK,
			"preset_rename": status.HTTP_200_OK,
		},
		"LogsViewSet": {
			"list": status.HTTP_200_OK,
			"reset": status.HTTP_200_OK,
			"truncate": status.HTTP_200_OK,
		},
		"LivenessViewSet": {
			"check": status.HTTP_200_OK,
		},
		"TOTPViewSet": {
			"list": status.HTTP_200_OK,
			"create_device": status.HTTP_201_CREATED,
			"validate_device": status.HTTP_200_OK,
			"delete_device": status.HTTP_200_OK,
			"delete_for_user": status.HTTP_200_OK,
		},
		"ApplicationGroupViewSet": {
			"create_info": status.HTTP_200_OK,
			"insert": status.HTTP_201_CREATED,
			"list": status.HTTP_200_OK,
			"retrieve": status.HTTP_200_OK,
			"update": status.HTTP_200_OK,
			"change_status": status.HTTP_200_OK,
			"delete": status.HTTP_200_OK,
		},
		"ApplicationViewSet": {
			"list": status.HTTP_200_OK,
			"fetch": status.HTTP_200_OK,
			"insert": status.HTTP_201_CREATED,
			"update": status.HTTP_200_OK,
			"delete": status.HTTP_200_OK,
		},
	}
