########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture, MockType
################################################################################
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from core.views.ldap.group import LDAPGroupsViewSet
from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework import status

@pytest.fixture(autouse=True)
def f_ldap_connector(g_ldap_connector) -> MockType:
	"""Fixture to mock LDAPConnector and its context manager."""
	return g_ldap_connector(patch_path="core.views.ldap.group.LDAPConnector")

@pytest.fixture
def f_runtime_settings(
	mocker: MockerFixture,
	g_runtime_settings: RuntimeSettingsSingleton
):
	mocker.patch("core.views.ldap.group.RuntimeSettings", g_runtime_settings)
	return g_runtime_settings

@pytest.fixture(autouse=True)
def f_interlock_ldap_enabled(g_interlock_ldap_enabled):
	return g_interlock_ldap_enabled

class TestList:
	endpoint = "/api/ldap/ou/"

class TestDirtree:
	endpoint = "/api/ldap/ou/dirtree/"

class TestMove:
	endpoint = "/api/ldap/ou/move/"

class TestRename:
	endpoint = "/api/ldap/ou/rename/"

class TestInsert:
	endpoint = "/api/ldap/ou/insert/"

class TestDelete:
	endpoint = "/api/ldap/ou/delete/"
