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
from rest_framework import status
from http import HTTPMethod
from pytest import FixtureRequest
from interlock_backend.test_settings import SIMPLE_JWT
from typing import Protocol
from django.urls import reverse

_ACCESS_NAME = SIMPLE_JWT["AUTH_COOKIE_NAME"]
_REFRESH_NAME = SIMPLE_JWT["REFRESH_COOKIE_NAME"]
_JWT_SAMESITE = SIMPLE_JWT["AUTH_COOKIE_SAME_SITE"]
_JWT_SECURE = SIMPLE_JWT["AUTH_COOKIE_SECURE"]


@pytest.fixture(
	params=[
		# LDAP Domain
		("/api/ldap/domain/details/", HTTPMethod.GET),
		("/api/ldap/domain/zones/", HTTPMethod.POST),
		("/api/ldap/domain/insert/", HTTPMethod.POST),
		("/api/ldap/domain/delete/", HTTPMethod.POST),
		# LDAP Record
		("/api/ldap/record/insert/", HTTPMethod.POST),
		("/api/ldap/record/update/", HTTPMethod.PUT),
		("/api/ldap/record/delete/", HTTPMethod.POST),
		# LDAP Groups
		("/api/ldap/groups/", HTTPMethod.GET),
		("/api/ldap/groups/fetch/", HTTPMethod.POST),
		("/api/ldap/groups/insert/", HTTPMethod.POST),
		("/api/ldap/groups/update/", HTTPMethod.PUT),
		("/api/ldap/groups/delete/", HTTPMethod.POST),
		# LDAP Users
		("/api/ldap/users/", HTTPMethod.GET),
		("/api/ldap/users/fetch/", HTTPMethod.POST),
		("/api/ldap/users/insert/", HTTPMethod.POST),
		("/api/ldap/users/update/", HTTPMethod.PUT),
		("/api/ldap/users/change_status/", HTTPMethod.POST),
		("/api/ldap/users/delete/", HTTPMethod.POST),
		("/api/ldap/users/change_password/", HTTPMethod.POST),
		("/api/ldap/users/unlock/", HTTPMethod.POST),
		("/api/ldap/users/bulk_insert/", HTTPMethod.POST),
		("/api/ldap/users/bulk_update/", HTTPMethod.POST),
		("/api/ldap/users/bulk_change_status/", HTTPMethod.POST),
		("/api/ldap/users/bulk_delete/", HTTPMethod.POST),
		("/api/ldap/users/bulk_unlock/", HTTPMethod.POST),
		("/api/ldap/users/self_change_password/", HTTPMethod.POST),
		("/api/ldap/users/self_update/", HTTPMethod.POST),
		("/api/ldap/users/self_info/", HTTPMethod.GET),
		("/api/ldap/users/self_fetch/", HTTPMethod.GET),
		# LDAP Directory Tree and OUs
		("/api/ldap/ou/", HTTPMethod.GET),
		("/api/ldap/ou/dirtree/", HTTPMethod.POST),
		("/api/ldap/ou/move/", HTTPMethod.POST),
		("/api/ldap/ou/rename/", HTTPMethod.POST),
		("/api/ldap/ou/insert/", HTTPMethod.POST),
		("/api/ldap/ou/delete/", HTTPMethod.POST),
		# Application Groups
		("/api/application/group/create_info/", HTTPMethod.GET),
		("/api/application/group/insert/", HTTPMethod.POST),
		("/api/application/group/", HTTPMethod.GET),
		("/api/application/group/{pk}/", HTTPMethod.GET),
		("/api/application/group/{pk}/", HTTPMethod.PUT),
		("/api/application/group/{pk}/change_status/", HTTPMethod.PATCH),
		("/api/application/group/{pk}/delete/", HTTPMethod.DELETE),
		# Application
		("/api/application/", HTTPMethod.GET),
		("/api/application/insert/", HTTPMethod.POST),
		("/api/application/{pk}/delete/", HTTPMethod.DELETE),
		("/api/application/{pk}/fetch/", HTTPMethod.GET),
		("/api/application/{pk}/", HTTPMethod.PUT),
	],
	ids=lambda x: f"{x[1]}: {x[0]}",
)
def g_all_endpoints(request: FixtureRequest):
	"""Returns tuple of (endpoint, method)"""
	return request.param


# Filtered fixture - only LDAP domain endpoints
ldap_endpoints = (
	# LDAP Domain
	"/api/ldap/domain/zones/",
	"/api/ldap/domain/insert/",
	"/api/ldap/domain/delete/",
	# LDAP Record
	"/api/ldap/record/insert/",
	"/api/ldap/record/update/",
	"/api/ldap/record/delete/",
	# LDAP Groups
	"/api/ldap/groups/",
	"/api/ldap/groups/fetch/",
	"/api/ldap/groups/insert/",
	"/api/ldap/groups/update/",
	"/api/ldap/groups/delete/",
	# LDAP Users
	"/api/ldap/users/",
	"/api/ldap/users/fetch/",
	"/api/ldap/users/insert/",
	"/api/ldap/users/update/",
	"/api/ldap/users/change_status/",
	"/api/ldap/users/delete/",
	"/api/ldap/users/change_password/",
	"/api/ldap/users/unlock/",
	"/api/ldap/users/bulk_insert/",
	"/api/ldap/users/bulk_update/",
	"/api/ldap/users/bulk_change_status/",
	"/api/ldap/users/bulk_delete/",
	"/api/ldap/users/bulk_unlock/",
	"/api/ldap/users/self_change_password/",
	"/api/ldap/users/self_update/",
	"/api/ldap/users/self_fetch/",
	# LDAP Directory Tree and OUs
	"/api/ldap/ou/",
	"/api/ldap/ou/dirtree/",
	"/api/ldap/ou/move/",
	"/api/ldap/ou/rename/",
	"/api/ldap/ou/insert/",
	"/api/ldap/ou/delete/",
)


@pytest.fixture(
	params=[
		# Access underlying params
		p
		for p in g_all_endpoints._pytestfixturefunction.params
		# Filter condition
		if p[0] in ldap_endpoints
	],
	ids=lambda x: f"{x[1].upper()}: {x[0]} (LDAP Required)",
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
)
def g_authenticated_endpoints(request: FixtureRequest):
	return request.param


excluded_from_admin_only = (
	"/api/ldap/domain/details/",
	"/api/ldap/users/self_change_password/",
	"/api/ldap/users/self_update/",
	"/api/ldap/users/self_fetch/",
	"/api/ldap/users/self_info/",
)


@pytest.fixture(
	params=[
		# Access underlying params
		p
		for p in g_all_endpoints._pytestfixturefunction.params
		# Filter condition
		if p[0] not in excluded_from_admin_only
	],
	ids=lambda x: f"{x[1].upper()}: {x[0]} (Admin Required)",
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
def f_application_group(f_application: Application, f_user_local, f_user_ldap):
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
def f_client(f_application: Application) -> Client:
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

class BaseViewTestClass:
	_endpoint = None

	@property
	def endpoint(self):
		if not self._endpoint:
			raise NotImplementedError("Test class requires an endpoint")
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
