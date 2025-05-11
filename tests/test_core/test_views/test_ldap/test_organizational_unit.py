########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture, MockType

################################################################################
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from core.models.user import User
from core.views.ldap.organizational_unit import LDAPOrganizationalUnitViewSet
from core.models.choices.log import (
	LOG_ACTION_CREATE,
	LOG_ACTION_DELETE,
	LOG_ACTION_READ,
	LOG_CLASS_LDAP,
	LOG_CLASS_OU,
	LOG_TARGET_ALL,
)
from logging import Logger
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
def f_logger(mocker: MockerFixture) -> Logger:
	m_logger = mocker.Mock(name="m_logger")
	mocker.patch("core.views.ldap.organizational_unit.logger", m_logger)
	return m_logger


@pytest.fixture(autouse=True)
def f_ldap_connector(g_ldap_connector) -> MockType:
	"""Fixture to mock LDAPConnector and its context manager."""
	return g_ldap_connector(
		patch_path="core.views.ldap.organizational_unit.LDAPConnector"
	)


@pytest.fixture
def f_runtime_settings(
	mocker: MockerFixture, g_runtime_settings: RuntimeSettingsSingleton
):
	mocker.patch(
		"core.views.ldap.organizational_unit.RuntimeSettings",
		g_runtime_settings,
	)
	return g_runtime_settings


@pytest.fixture(autouse=True)
def f_interlock_ldap_enabled(g_interlock_ldap_enabled):
	return g_interlock_ldap_enabled


class TestList:
	endpoint = "/api/ldap/ou/"

	def test_ldap_tree_raises(
		self, mocker: MockerFixture, admin_user_client: APIClient
	):
		mocker.patch(
			"core.views.ldap.organizational_unit.LDAPTree",
			side_effect=Exception,
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
		f_log_mixin: LogMixin,
	):
		# Mock Perfcounter setting
		mocker.patch(
			"core.views.ldap.organizational_unit.DIRTREE_PERF_LOGGING", True
		)
		m_perf_counter = mocker.patch(
			"core.views.ldap.organizational_unit.perf_counter"
		)

		m_ldap_tree_instance = mocker.Mock()
		m_ldap_tree_instance.children = ["children"]
		m_ldap_tree_cls = mocker.patch(
			"core.views.ldap.organizational_unit.LDAPTree",
			return_value=m_ldap_tree_instance,
		)
		response: Response = admin_user_client.get(self.endpoint)
		m_ldap_tree_cls.assert_called_once_with(
			**{
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
			}
		)
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

	def test_ldap_tree_raises(
		self, mocker: MockerFixture, admin_user_client: APIClient
	):
		# Mock process_ldap_filter
		m_filter = mocker.Mock(name="m_filter")
		m_filter_str = "fake_filter"
		m_filter.to_string = mocker.Mock(
			name="m_filter_to_string", return_value=m_filter_str
		)
		mocker.patch.object(
			LDAPOrganizationalUnitViewSet,
			"process_ldap_filter",
			return_value=m_filter,
		)

		# Mock LDAPTree
		mocker.patch(
			"core.views.ldap.organizational_unit.LDAPTree",
			side_effect=Exception,
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
			name="m_filter_to_string", return_value=m_filter_str
		)
		m_process_ldap_filter = mocker.patch.object(
			LDAPOrganizationalUnitViewSet,
			"process_ldap_filter",
			return_value=m_filter,
		)

		# Mock Perfcounter setting
		mocker.patch(
			"core.views.ldap.organizational_unit.DIRTREE_PERF_LOGGING", True
		)
		m_perf_counter = mocker.patch(
			"core.views.ldap.organizational_unit.perf_counter"
		)

		# Mock LDAPTree
		m_ldap_tree_instance = mocker.Mock()
		m_ldap_tree_instance.children = ["children"]
		m_ldap_tree_cls = mocker.patch(
			"core.views.ldap.organizational_unit.LDAPTree",
			return_value=m_ldap_tree_instance,
		)

		# Execute
		response: Response = admin_user_client.post(
			self.endpoint, data={"filter": {}}, format="json"
		)

		# Assertions
		m_process_ldap_filter.assert_called_once_with(
			data_filter={},
			default_filter=None,
		)
		m_ldap_tree_cls.assert_called_once_with(
			**{
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
			}
		)
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
			LDAPOrganizationalUnitViewSet, "move_or_rename_object"
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
			format="json",
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
			LDAPOrganizationalUnitViewSet, "move_or_rename_object"
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
			format="json",
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
			LDAPOrganizationalUnitViewSet, "move_or_rename_object"
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
			format="json",
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
			LDAPOrganizationalUnitViewSet, "move_or_rename_object"
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
			format="json",
		)
		m_move_or_rename_object.assert_called_once_with(
			distinguished_name=m_distinguished_name,
			target_rdn=m_new_rdn,
		)
		f_ldap_connector.cls_mock.assert_called_once_with(admin_user)
		assert response.status_code == status.HTTP_200_OK


class TestInsert:
	endpoint = "/api/ldap/ou/insert/"

	def test_raises_bad_request_no_object(
		self,
		admin_user_client: APIClient,
		f_ldap_connector: LDAPConnectorMock,
	):
		# Execute
		response: Response = admin_user_client.post(self.endpoint, data={})
		f_ldap_connector.connection.add.assert_not_called()
		f_ldap_connector.cls_mock.assert_not_called()
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert "ldapObject dict is required in data" in response.data.get(
			"detail"
		)

	@pytest.mark.parametrize(
		"object_type",
		("some_bad_type", None),
	)
	def test_raises_bad_request_on_type(
		self,
		object_type: str,
		admin_user_client: APIClient,
		f_ldap_connector: LDAPConnectorMock,
	):
		# Execute
		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				"ldapObject": {
					"name": "mock_name",
					"path": "mock_path",
					"type": object_type,
				}
			},
			format="json",
		)
		f_ldap_connector.connection.add.assert_not_called()
		f_ldap_connector.cls_mock.assert_not_called()
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert "object type must be one of" in response.data.get("detail")

	@pytest.mark.parametrize(
		"field_to_test",
		(
			"name",
			"path",
			"type",
		),
	)
	def test_raises_missing_field(
		self,
		field_to_test: str,
		admin_user_client: APIClient,
		f_ldap_connector: LDAPConnectorMock,
	):
		m_data = {
			"name": "mock_name",
			"path": "mock_path",
			"type": "mock_type",
		}
		del m_data[field_to_test]

		# Execute
		response: Response = admin_user_client.post(
			self.endpoint, data={"ldapObject": m_data}, format="json"
		)
		f_ldap_connector.connection.add.assert_not_called()
		f_ldap_connector.cls_mock.assert_not_called()
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("field") == field_to_test

	@pytest.mark.parametrize(
		"ldap_result_description, expected_code",
		(
			("genericException", status.HTTP_500_INTERNAL_SERVER_ERROR),
			("entryAlreadyExists", status.HTTP_409_CONFLICT),
		),
	)
	def test_ldap_add_raises(
		self,
		mocker: MockerFixture,
		ldap_result_description: str,
		expected_code: int,
		admin_user: User,
		admin_user_client: APIClient,
		f_ldap_connector: LDAPConnectorMock,
		f_log_mixin: LogMixin,
		f_logger: Logger,
	):
		m_result = mocker.Mock(name="mock_result")
		m_result.description = ldap_result_description
		f_ldap_connector.connection.result = m_result
		f_ldap_connector.connection.add.side_effect = Exception

		# Execute
		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				"ldapObject": {
					"name": "mock_name",
					"path": "mock_path",
					"type": "ou",
				}
			},
			format="json",
		)

		# Assertions
		f_ldap_connector.cls_mock.assert_called_once_with(admin_user)
		f_ldap_connector.connection.add.assert_called_once()
		f_log_mixin.log.assert_not_called()
		f_logger.exception.assert_called_once()
		f_logger.error.assert_called_once()
		assert response.status_code == expected_code

	@pytest.mark.parametrize(
		"object_type",
		(
			"ou",
			"computer",
			"printer",
		),
	)
	def test_success(
		self,
		object_type: str,
		admin_user: User,
		admin_user_client: APIClient,
		f_ldap_connector: LDAPConnectorMock,
		f_log_mixin: LogMixin,
	):
		m_name = "mock_name"
		m_path = "mock_path"
		m_ldap_object = {
			"name": m_name,
			"path": m_path,
			"type": object_type,
		}
		prefix = "OU" if object_type == "ou" else "CN"
		expected_attrs = {"name": m_name}
		if object_type == "ou":
			expected_attrs["ou"] = m_name

		# Execute
		response: Response = admin_user_client.post(
			self.endpoint, data={"ldapObject": m_ldap_object}, format="json"
		)

		# Assertions
		f_ldap_connector.cls_mock.assert_called_once_with(admin_user)
		f_ldap_connector.connection.add.assert_called_once_with(
			dn=f"{prefix}={m_name},{m_path}",
			object_class=object_type
			if object_type != "ou"
			else "organizationalUnit",
			attributes=expected_attrs,
		)
		f_log_mixin.log.assert_called_once_with(
			user=admin_user.id,
			operation_type=LOG_ACTION_CREATE,
			log_target_class=LOG_CLASS_OU,
			log_target=m_name,
		)
		assert response.status_code == status.HTTP_200_OK


class TestDelete:
	endpoint = "/api/ldap/ou/delete/"

	def test_raises_not_exists(
		self,
		admin_user_client: APIClient,
		f_ldap_connector: LDAPConnectorMock,
	):
		# Execute
		response: Response = admin_user_client.post(
			self.endpoint, data={"distinguishedName": None}, format="json"
		)
		f_ldap_connector.cls_mock.assert_not_called()
		assert response.status_code == status.HTTP_409_CONFLICT
		assert response.data.get("code") == "ldap_obj_doesnt_exist"

	def test_raises_ldap_exc(
		self,
		mocker: MockerFixture,
		admin_user: User,
		admin_user_client: APIClient,
		f_ldap_connector: LDAPConnectorMock,
	):
		f_ldap_connector.connection.result = mocker.Mock(name="mock_result")
		f_ldap_connector.connection.result.description = "someDescription"
		f_ldap_connector.connection.delete.side_effect = Exception

		# Execute
		response: Response = admin_user_client.post(
			self.endpoint, data={"distinguishedName": "mock_dn"}, format="json"
		)
		f_ldap_connector.connection.delete.assert_called_once_with(dn="mock_dn")
		f_ldap_connector.cls_mock.assert_called_once_with(admin_user)
		assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

	def test_success(
		self,
		admin_user: User,
		admin_user_client: APIClient,
		f_ldap_connector: LDAPConnectorMock,
		f_log_mixin: LogMixin,
	):
		# Execute
		response: Response = admin_user_client.post(
			self.endpoint,
			data={"name": "mock_name", "distinguishedName": "mock_dn"},
			format="json",
		)
		f_ldap_connector.connection.delete.assert_called_once_with(dn="mock_dn")
		f_ldap_connector.cls_mock.assert_called_once_with(admin_user)
		f_log_mixin.log.assert_called_once_with(
			user=admin_user.id,
			operation_type=LOG_ACTION_DELETE,
			log_target_class=LOG_CLASS_LDAP,
			log_target="mock_name",
		)
		assert response.status_code == status.HTTP_200_OK
