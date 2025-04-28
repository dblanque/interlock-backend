# conftest.py
import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from core.ldap.defaults import LDAP_DOMAIN
import pytest
from typing import Protocol
from rest_framework import status
from pytest import FixtureRequest

User = get_user_model()

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
	ids=lambda x: f"{x[1].upper()}: {x[0]}"
)
def g_all_endpoints(request: FixtureRequest):
	"""Returns tuple of (endpoint, method)"""
	return request.param

# Filtered fixture - only LDAP domain endpoints
excluded_from_ldap = (
	"/api/ldap/domain/details/",
)
@pytest.fixture(
    params=[
		# Access underlying params
        p for p in g_all_endpoints._pytestfixturefunction.params
		# Filter condition
        if p[0] not in excluded_from_ldap
    ],
    ids=lambda x: f"{x[1].upper()}: {x[0]} (LDAP Required)"
)
def g_ldap_domain_endpoints(request: FixtureRequest):
    return request.param

# Filtered fixture - only LDAP domain endpoints
excluded_from_auth = (
	"/api/ldap/domain/details/",
)
@pytest.fixture(
    params=[
		# Access underlying params
        p for p in g_all_endpoints._pytestfixturefunction.params
		# Filter condition
        if p[0] not in excluded_from_auth
    ],
    ids=lambda x: f"{x[1].upper()}: {x[0]} (Auth. Required)"
)
def g_authenticated_endpoints(request: FixtureRequest):
    return request.param

@pytest.fixture
def api_client():
	"""Unauthenticated API client"""
	return APIClient()


@pytest.fixture
def user_factory(db):
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
	disabled_user, api_client: APIClient
) -> DisabledApiClient:
	"""Authenticated API client for normal user"""
	api_client.post(
		"/api/token/",
		data={
			"username": disabled_user.username,
			"password": disabled_user.raw_password,
		},
	)
	return api_client


class NormalApiClient(Protocol):
	def __call__(self) -> APIClient: ...


@pytest.fixture
def normal_user_client(normal_user, api_client: APIClient) -> NormalApiClient:
	"""Authenticated API client for normal user"""
	api_client.post(
		"/api/token/",
		data={
			"username": normal_user.username,
			"password": normal_user.raw_password,
		},
	)
	return api_client


class AdminApiClient(Protocol):
	def __call__(self) -> APIClient: ...


@pytest.fixture
def admin_user_client(admin_user, api_client: APIClient) -> AdminApiClient:
	"""Authenticated API client for admin user"""
	api_client.post(
		"/api/token/",
		data={
			"username": admin_user.username,
			"password": admin_user.raw_password,
		},
	)
	return api_client


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
