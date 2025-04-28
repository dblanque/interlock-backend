########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType

################################################################################
from rest_framework.response import Response
from rest_framework import status
from core.views.ldap.user import LDAPUserViewSet
from rest_framework.test import APIClient
from core.exceptions.ldap import CouldNotOpenConnection


@pytest.fixture(autouse=True)
def f_ldap_connector(g_ldap_connector) -> MockType:
	"""Fixture to mock LDAPConnector and its context manager."""
	return g_ldap_connector(patch_path="core.views.ldap.user.LDAPConnector")


@pytest.fixture(autouse=True)
def f_interlock_ldap_enabled(g_interlock_ldap_enabled):
	return g_interlock_ldap_enabled


class TestList:
	@staticmethod
	def test_list_users_success(
		admin_user_client: APIClient, mocker: MockerFixture
	):
		"""Test successful user listing"""
		# Mock LDAP connection and data
		m_ldap_users = {
			"users": [{"username": "testuser", "is_enabled": True}],
			"headers": ["username", "is_enabled"],
		}

		# Patch the ldap_user_list method to return our mock data
		mocker.patch.object(
			LDAPUserViewSet, "ldap_user_list", return_value=m_ldap_users
		)

		# Make API call
		response: Response = admin_user_client.get("/api/ldap/users/")

		# Assertions
		assert response.status_code == status.HTTP_200_OK
		assert response.data["code"] == 0
		assert len(response.data["users"]) == 1
		assert "username" in response.data["headers"]

	@staticmethod
	def test_list_users_unauthenticated(api_client):
		"""Test unauthenticated access"""
		response = api_client.get("/api/ldap/users/")
		assert response.status_code == status.HTTP_401_UNAUTHORIZED

	@staticmethod
	def test_list_users_ldap_error(admin_user_client, mocker):
		"""Test LDAP connection failure"""
		# Mock LDAPConnector to raise an exception
		mocker.patch(
			"core.views.ldap.user.LDAPConnector",
			side_effect=CouldNotOpenConnection,
		)

		response = admin_user_client.get("/api/ldap/users/")
		assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE

	@staticmethod
	def test_list_users_ldap_error(admin_user_client, mocker):
		"""Test LDAP connection failure"""
		# Mock LDAPConnector to raise an exception
		mocker.patch(
			"core.views.ldap.user.LDAPConnector",
			side_effect=CouldNotOpenConnection,
		)

		response = admin_user_client.get("/api/ldap/users/")
		assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
