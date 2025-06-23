########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType

################################################################################
from django.urls import reverse
from tests.test_core.conftest import (
	LDAPConnectorMock,
	ConnectorFactory,
	RuntimeSettingsFactory,
)
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from tests.test_core.test_views.conftest import UserFactory
from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework import status
from core.models.interlock_settings import InterlockSetting
from core.models.user import USER_TYPE_LDAP, User


@pytest.fixture
def f_connector(mocker: MockerFixture, g_ldap_connector: ConnectorFactory):
	return g_ldap_connector(
		patch_path="core.views.home.LDAPConnector",
		attrs_connection={
			# Mock CONNECTION_OPEN, CONNECTION_CLOSE
			"bound": mocker.PropertyMock(
				name="m_bound",
				side_effect=(
					True,
					False,
				),
			)
		},
	)


@pytest.fixture(autouse=True)
def f_runtime_settings(g_runtime_settings: RuntimeSettingsFactory):
	return g_runtime_settings(patch_path="core.views.home.RuntimeSettings")


@pytest.fixture
def f_users(user_factory: UserFactory):
	m_users = [
		user_factory(username=f"test_c_{n}", email=f"test_c_{n}@example.com")
		for n in range(4)
	]
	for n in range(0, 3):
		m_users[n].user_type = USER_TYPE_LDAP
		m_users[n].save()
		m_users[n].refresh_from_db()
	return m_users


class TestList:
	endpoint = reverse("home-list")

	@pytest.mark.django_db
	@pytest.mark.parametrize(
		"use_tls, use_ssl",
		(
			(
				False,
				False,
			),
			(
				True,
				False,
			),
			(
				False,
				True,
			),
		),
	)
	def test_success_ldap_enabled(
		self,
		mocker: MockerFixture,
		f_users: list[User],
		f_connector: LDAPConnectorMock,
		admin_user_client: APIClient,
		g_interlock_ldap_enabled,
		f_runtime_settings: RuntimeSettingsSingleton,
		use_tls: bool,
		use_ssl: bool,
	):
		f_runtime_settings.LDAP_AUTH_USE_TLS = use_tls
		f_runtime_settings.LDAP_AUTH_USE_SSL = use_ssl

		m_server = mocker.Mock(name="m_server")
		m_server.name = "ldaps://127.0.0.1:636" if use_ssl or use_tls\
			else "ldap://127.0.0.1:389"
		m_server.host = "127.0.0.1"
		m_server.ssl = use_ssl
		f_connector.connection.server_pool.get_current_server.return_value = (
			m_server
		)

		response: Response = admin_user_client.get(self.endpoint)

		assert response.status_code == status.HTTP_200_OK
		data: dict = response.data.get("data")
		assert data.get("ldap_ok") is True
		assert data.get("ldap_active_server") == "127.0.0.1"
		assert data.get("local_user_count") == 2
		assert data.get("ldap_user_count") == 3
		assert data.get("ldap_tls") == use_tls or m_server.name.startswith("ldaps://")
		assert data.get("ldap_ssl") == use_ssl

	@pytest.mark.parametrize(
		"setting_exists",
		(
			True,
			False,
		),
	)
	def test_success_ldap_disabled(
		self,
		mocker: MockerFixture,
		setting_exists: bool,
		f_users: list[User],
		f_connector: LDAPConnectorMock,
		admin_user_client: APIClient,
		g_interlock_ldap_disabled: InterlockSetting,
	):
		if not setting_exists:
			g_interlock_ldap_disabled.delete_permanently()
		m_server = mocker.Mock(name="m_server")
		m_server.host = "127.0.0.1"
		f_connector.connection.server_pool.get_current_server.return_value = (
			m_server
		)

		response: Response = admin_user_client.get(self.endpoint)

		assert response.status_code == status.HTTP_200_OK
		data: dict = response.data.get("data")
		assert not data.get("ldap_ok")
		assert data.get("ldap_active_server") == None
		assert data.get("local_user_count") == 2
		assert data.get("ldap_user_count") == 0

	def test_success_with_ldap_connector_exception(
		self,
		mocker: MockerFixture,
		f_connector: LDAPConnectorMock,
		admin_user_client: APIClient,
		g_interlock_ldap_enabled,
	):
		f_connector.connection.server_pool.get_current_server.side_effect = (
			Exception
		)

		response: Response = admin_user_client.get(self.endpoint)

		assert response.status_code == status.HTTP_200_OK
		data: dict = response.data.get("data")
		assert not data.get("ldap_ok")
		assert data.get("ldap_active_server") == None
