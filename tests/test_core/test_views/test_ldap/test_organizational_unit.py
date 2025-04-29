########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture, MockType
################################################################################
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from core.models.user import User
from core.views.ldap.organizational_unit import LDAPOrganizationalUnitViewSet
from core.models.choices.log import (
	LOG_ACTION_READ,
	LOG_CLASS_LDAP,
	LOG_CLASS_OU,
	LOG_TARGET_ALL,
)
from core.views.mixins.logs import LogMixin
from tests.test_core.type_hints import LDAPConnectorMock
from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework import status

@pytest.fixture(autouse=True)
def f_log_mixin(mocker: MockerFixture):
	m_log_mixin = mocker.Mock(name="f_log_mixin")
	mocker.patch("core.views.ldap.organizational_unit.DBLogMixin", m_log_mixin)
	return m_log_mixin

@pytest.fixture(autouse=True)
def f_ldap_connector(g_ldap_connector) -> MockType:
	"""Fixture to mock LDAPConnector and its context manager."""
	return g_ldap_connector(patch_path="core.views.ldap.organizational_unit.LDAPConnector")

@pytest.fixture
def f_runtime_settings(
	mocker: MockerFixture,
	g_runtime_settings: RuntimeSettingsSingleton
):
	mocker.patch("core.views.ldap.organizational_unit.RuntimeSettings", g_runtime_settings)
	return g_runtime_settings

@pytest.fixture(autouse=True)
def f_interlock_ldap_enabled(g_interlock_ldap_enabled):
	return g_interlock_ldap_enabled

class TestList:
	endpoint = "/api/ldap/ou/"

	def test_ldap_tree_raises(self, mocker: MockerFixture, admin_user_client: APIClient):
		mocker.patch(
			"core.views.ldap.organizational_unit.LDAPTree",
			side_effect=Exception
		)
		response: Response = admin_user_client.get(self.endpoint)
		assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
		assert response.data["code"] == "ldap_tree_err"

	def test_success_with_perf_counter(
			self,
			mocker: MockerFixture,
			admin_user: User,
			admin_user_client: APIClient,
			f_ldap_connector: LDAPConnectorMock,
			f_runtime_settings: RuntimeSettingsSingleton,
			f_log_mixin: LogMixin
		):
		# Mock Perfcounter setting
		mocker.patch(
			"core.views.ldap.organizational_unit.DIRTREE_PERF_LOGGING",
			True
		)
		m_perf_counter = mocker.patch("core.views.ldap.organizational_unit.perf_counter")

		m_ldap_tree_instance = mocker.Mock()
		m_ldap_tree_instance.children = ["children"]
		m_ldap_tree_cls = mocker.patch(
			"core.views.ldap.organizational_unit.LDAPTree",
			return_value=m_ldap_tree_instance
		)
		response: Response = admin_user_client.get(self.endpoint)
		m_ldap_tree_cls.assert_called_once_with(**{
			"connection": f_ldap_connector.connection,
			"recursive": True,
			"ldap_filter": "(|(objectCategory=organizationalUnit)(objectCategory=top)(objectCategory=container)(objectClass=builtinDomain))",
			"ldap_attrs": [
				# User Attrs
				"objectClass",
				"objectCategory",
				f_runtime_settings.LDAP_OU_FIELD,
				# Group Attrs
				"cn",
				"member",
				"distinguishedName",
				"groupType",
				"objectSid",
			],
		})
		m_perf_counter.call_count == 2
		f_log_mixin.log.assert_called_once_with(
			user=admin_user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_OU,
			log_target=LOG_TARGET_ALL,
		)
		assert response.status_code == status.HTTP_200_OK
		assert response.data.get("ldapObjectList") == ["children"]

class TestDirtree:
	endpoint = "/api/ldap/ou/dirtree/"

	def test_ldap_tree_raises(self, mocker: MockerFixture, admin_user_client: APIClient):
		# Mock process_ldap_filter
		m_filter = mocker.Mock(name="m_filter")
		m_filter_str = "fake_filter"
		m_filter.to_string = mocker.Mock(
			name="m_filter_to_string",
			return_value=m_filter_str
		)
		mocker.patch.object(
			LDAPOrganizationalUnitViewSet,
			"process_ldap_filter",
			return_value=m_filter
		)

		# Mock LDAPTree
		mocker.patch(
			"core.views.ldap.organizational_unit.LDAPTree",
			side_effect=Exception
		)
		response: Response = admin_user_client.post(self.endpoint)
		assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
		assert response.data["code"] == "ldap_tree_err"

	def test_success_with_perf_counter(
			self,
			mocker: MockerFixture,
			admin_user: User,
			admin_user_client: APIClient,
			f_ldap_connector: LDAPConnectorMock,
			f_runtime_settings: RuntimeSettingsSingleton,
			f_log_mixin: LogMixin,
		):
		# Mock process_ldap_filter
		m_filter = mocker.Mock(name="m_filter")
		m_filter_str = "fake_filter"
		m_filter.to_string = mocker.Mock(
			name="m_filter_to_string",
			return_value=m_filter_str
		)
		m_process_ldap_filter = mocker.patch.object(
			LDAPOrganizationalUnitViewSet,
			"process_ldap_filter",
			return_value=m_filter
		)

		# Mock Perfcounter setting
		mocker.patch(
			"core.views.ldap.organizational_unit.DIRTREE_PERF_LOGGING",
			True
		)
		m_perf_counter = mocker.patch("core.views.ldap.organizational_unit.perf_counter")

		# Mock LDAPTree
		m_ldap_tree_instance = mocker.Mock()
		m_ldap_tree_instance.children = ["children"]
		m_ldap_tree_cls = mocker.patch(
			"core.views.ldap.organizational_unit.LDAPTree",
			return_value=m_ldap_tree_instance
		)

		# Execute
		response: Response = admin_user_client.post(
			self.endpoint,
			data={"filter":{}},
			format="json"
		)

		# Assertions
		m_process_ldap_filter.assert_called_once_with(
			data_filter={},
			default_filter=None,
		)
		m_ldap_tree_cls.assert_called_once_with(**{
			"connection": f_ldap_connector.connection,
			"recursive": True,
			"ldap_filter": m_filter_str,
			"ldap_attrs": [
				# User Attrs
				"objectClass",
				"objectCategory",
				f_runtime_settings.LDAP_OU_FIELD,
				# Group Attrs
				"cn",
				"member",
				"distinguishedName",
				"groupType",
			],
		})
		m_perf_counter.call_count == 2
		f_log_mixin.log.assert_called_once_with(
			user=admin_user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_LDAP,
			log_target=LOG_TARGET_ALL,
		)
		assert response.status_code == status.HTTP_200_OK
		assert response.data.get("ldapObjectList") == ["children"]


class TestMove:
	endpoint = "/api/ldap/ou/move/"

	@pytest.mark.parametrize(
		"ldap_path, distinguished_name, expected_match",
		(
			("", "mock_dn", "destination is required"),
			("mock_path", "", "distinguishedName is required"),
		),
	)
	def test_raises_bad_request(
		self,
		ldap_path: str,
		distinguished_name: str,
		expected_match: str,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		f_ldap_connector: LDAPConnectorMock,
	):
		m_move_or_rename_object = mocker.patch.object(
			LDAPOrganizationalUnitViewSet,
			"move_or_rename_object"
		)

		# Execute
		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				"ldapObject": {
					"destination": ldap_path,
					"distinguishedName": distinguished_name,
				}
			},
			format="json"
		)
		f_ldap_connector.cls_mock.assert_not_called()
		m_move_or_rename_object.assert_not_called()
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert expected_match in response.data.get("detail")

	def test_success(
		self,
		mocker: MockerFixture,
		admin_user: User,
		admin_user_client: APIClient,
		f_ldap_connector: LDAPConnectorMock,
	):
		m_move_or_rename_object = mocker.patch.object(
			LDAPOrganizationalUnitViewSet,
			"move_or_rename_object"
		)
		m_distinguished_name = "mock_dn"
		m_ldap_path = "mock_path"

		# Execute
		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				"ldapObject": {
					"distinguishedName": m_distinguished_name,
					"destination": m_ldap_path,
				}
			},
			format="json"
		)
		m_move_or_rename_object.assert_called_once_with(
			distinguished_name=m_distinguished_name,
			target_path=m_ldap_path,
		)
		f_ldap_connector.cls_mock.assert_called_once_with(admin_user)
		assert response.status_code == status.HTTP_200_OK

class TestRename:
	endpoint = "/api/ldap/ou/rename/"

	@pytest.mark.parametrize(
		"new_rdn, distinguished_name, expected_match",
		(
			("", "mock_dn", "newRDN is required"),
			("mock_rdn", "", "distinguishedName is required"),
		),
	)
	def test_raises_bad_request(
		self,
		new_rdn: str,
		distinguished_name: str,
		expected_match: str,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		f_ldap_connector: LDAPConnectorMock,
	):
		m_move_or_rename_object = mocker.patch.object(
			LDAPOrganizationalUnitViewSet,
			"move_or_rename_object"
		)

		# Execute
		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				"ldapObject": {
					"newRDN": new_rdn,
					"distinguishedName": distinguished_name,
				}
			},
			format="json"
		)
		f_ldap_connector.cls_mock.assert_not_called()
		m_move_or_rename_object.assert_not_called()
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert expected_match in response.data.get("detail")

	def test_success(
		self,
		mocker: MockerFixture,
		admin_user: User,
		admin_user_client: APIClient,
		f_ldap_connector: LDAPConnectorMock,
	):
		m_move_or_rename_object = mocker.patch.object(
			LDAPOrganizationalUnitViewSet,
			"move_or_rename_object"
		)
		m_distinguished_name = "mock_dn"
		m_new_rdn = "mock_rdn"

		# Execute
		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				"ldapObject": {
					"distinguishedName": m_distinguished_name,
					"newRDN": m_new_rdn,
				}
			},
			format="json"
		)
		m_move_or_rename_object.assert_called_once_with(
			distinguished_name=m_distinguished_name,
			target_rdn=m_new_rdn,
		)
		f_ldap_connector.cls_mock.assert_called_once_with(admin_user)
		assert response.status_code == status.HTTP_200_OK

class TestInsert:
	endpoint = "/api/ldap/ou/insert/"

class TestDelete:
	endpoint = "/api/ldap/ou/delete/"
