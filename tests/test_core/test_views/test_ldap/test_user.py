########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture
################################################################################
from rest_framework.response import Response
from rest_framework import status
from core.views.ldap.user import LDAPUserViewSet
from rest_framework.test import APIClient
from core.exceptions.ldap import CouldNotOpenConnection
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from tests.test_core.conftest import RuntimeSettingsFactory
from logging import Logger
from core.ldap.adsi import (
	LDAP_UF_DONT_EXPIRE_PASSWD,
	LDAP_UF_ACCOUNT_DISABLE,
	LDAP_UF_NORMAL_ACCOUNT,
)
from core.models.user import User, USER_TYPE_LDAP, USER_PASSWORD_FIELDS
from core.exceptions import (
	ldap as exc_ldap,
	users as exc_users,
)
from core.constants.attrs.local import *
from core.views.mixins.logs import LogMixin
from core.models.choices.log import (
	LOG_ACTION_UPDATE,
	LOG_CLASS_USER,
	LOG_EXTRA_USER_CHANGE_PASSWORD,
)
from tests.test_core.type_hints import LDAPConnectorMock
from interlock_backend.encrypt import aes_encrypt, aes_decrypt

@pytest.fixture(autouse=True)
def f_log_mixin(mocker: MockerFixture):
	m_log_mixin = mocker.Mock(name="m_log_mixin")
	mocker.patch("core.views.ldap.user.DBLogMixin", m_log_mixin)
	return m_log_mixin

@pytest.fixture(autouse=True)
def f_logger(mocker: MockerFixture):
	return mocker.patch(
		"core.views.ldap.user.logger",
		mocker.Mock(name="m_logger")
	)

@pytest.fixture(autouse=True)
def f_ldap_connector(g_ldap_connector) -> LDAPConnectorMock:
	"""Fixture to mock LDAPConnector and its context manager."""
	return g_ldap_connector(patch_path="core.views.ldap.user.LDAPConnector")


@pytest.fixture(autouse=True)
def f_interlock_ldap_enabled(g_interlock_ldap_enabled):
	return g_interlock_ldap_enabled


@pytest.fixture
def f_runtime_settings(g_runtime_settings: RuntimeSettingsFactory):
	return g_runtime_settings("core.views.ldap.user.RuntimeSettings")


class TestList:
	endpoint = "/api/ldap/users/"

	def test_list_users_success(
		self,
		admin_user_client: APIClient,
		mocker: MockerFixture,
	):
		"""Test successful user listing"""
		# Mock LDAP connection and data
		m_ldap_users = {
			"users": [
				{
					LOCAL_ATTR_USERNAME: "testuser",
					LOCAL_ATTR_IS_ENABLED: True
				},
			],
			"headers": [LOCAL_ATTR_USERNAME, LOCAL_ATTR_IS_ENABLED],
		}

		# Patch the ldap_user_list method to return our mock data
		mocker.patch.object(
			LDAPUserViewSet, "ldap_user_list", return_value=m_ldap_users
		)

		# Make API call
		response: Response = admin_user_client.get(self.endpoint)

		# Assertions
		assert response.status_code == status.HTTP_200_OK
		assert response.data["code"] == 0
		assert len(response.data["users"]) == 1
		assert LOCAL_ATTR_USERNAME in response.data["headers"]

	def test_list_users_ldap_error(
		self,
		admin_user_client: APIClient,
		mocker: MockerFixture,
	):
		"""Test LDAP connection failure"""
		# Mock LDAPConnector to raise an exception
		mocker.patch(
			"core.views.ldap.user.LDAPConnector",
			side_effect=CouldNotOpenConnection,
		)

		response: Response = admin_user_client.get(self.endpoint)
		assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE

	def test_list_users_ldap_error(
		self,
		admin_user_client: APIClient,
		mocker: MockerFixture,
	):
		"""Test LDAP connection failure"""
		# Mock LDAPConnector to raise an exception
		mocker.patch(
			"core.views.ldap.user.LDAPConnector",
			side_effect=CouldNotOpenConnection,
		)

		response: Response = admin_user_client.get(self.endpoint)
		assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE


class TestFetch:
	endpoint = "/api/ldap/users/fetch/"

	def test_raises_bad_request(
		self,
		admin_user_client: APIClient,
		mocker: MockerFixture,
	):
		mocker.patch.object(LDAPUserViewSet, "ldap_user_fetch")
		response: Response = admin_user_client.post(
			self.endpoint, data={"some_dict": "without_the_proper_keys"}
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST

	def test_success(
		self,
		admin_user_client: APIClient,
		mocker: MockerFixture,
	):
		m_result = {"mock": "result"}
		m_ldap_user_fetch = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_fetch", return_value=m_result
		)
		response: Response = admin_user_client.post(
			self.endpoint, data={LOCAL_ATTR_USERNAME: "testuser"}
		)
		m_ldap_user_fetch.assert_called_once_with(user_search="testuser")
		assert response.status_code == status.HTTP_200_OK
		assert response.data.get("data") == m_result


class TestInsert:
	endpoint = "/api/ldap/users/insert/"

	@pytest.mark.parametrize(
		"m_data, use_email",
		(
			(
				{
					LOCAL_ATTR_USERNAME: "testuser",
					LOCAL_ATTR_PATH: "OU=mock ou,DC=example,DC=com",
					LOCAL_ATTR_FIRST_NAME: "Test",
					LOCAL_ATTR_LAST_NAME: "User",
					LOCAL_ATTR_PASSWORD: "TestPassword",
					LOCAL_ATTR_PASSWORD_CONFIRM: "TestPassword",
					LOCAL_ATTR_PERMISSIONS: [
						LDAP_UF_DONT_EXPIRE_PASSWD,
						LDAP_UF_NORMAL_ACCOUNT,
					],
				},
				True,
			),
			(
				{
					LOCAL_ATTR_USERNAME: "testuser",
					LOCAL_ATTR_PATH: "OU=mock ou,DC=example,DC=com",
					LOCAL_ATTR_FIRST_NAME: "Test",
					LOCAL_ATTR_LAST_NAME: "User",
					LOCAL_ATTR_PASSWORD: "TestPassword",
					LOCAL_ATTR_PASSWORD_CONFIRM: "TestPassword",
					LOCAL_ATTR_PERMISSIONS: [
						LDAP_UF_DONT_EXPIRE_PASSWD,
						LDAP_UF_NORMAL_ACCOUNT,
					],
				},
				False,
			),
		),
	)
	def test_success(
		self,
		m_data: dict,
		use_email: bool,
		admin_user_client: APIClient,
		mocker: MockerFixture,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		m_distinguished_name = (
			f"CN=testuser,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}"
		)
		if use_email:
			m_data[LOCAL_ATTR_EMAIL] = (
				f"testuser@{f_runtime_settings.LDAP_DOMAIN}"
			)
		expected_m_data_call = m_data.copy()
		expected_m_data_call.pop(LOCAL_ATTR_PASSWORD_CONFIRM, None)

		m_ldap_user_exists = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_exists", return_value=False
		)
		m_ldap_user_insert = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_user_insert",
			return_value=m_distinguished_name,
		)
		m_ldap_set_password = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_set_password",
		)

		# Exec
		response: Response = admin_user_client.post(
			self.endpoint,
			data=m_data,
			format="json",
		)

		# Asserts
		assert response.status_code == status.HTTP_200_OK
		m_ldap_user_exists.assert_called_once_with(
			username="testuser",
			email=None
			if not use_email
			else m_data.get(
				f_runtime_settings.LDAP_FIELD_MAP[LOCAL_ATTR_EMAIL]
			),
		)
		m_ldap_user_insert.assert_called_once_with(
			data=expected_m_data_call
		)
		m_ldap_set_password.assert_called_once_with(
			user_dn=m_distinguished_name,
			user_pwd_new=m_data.get(LOCAL_ATTR_PASSWORD),
			set_by_admin=True,
		)

	@pytest.mark.parametrize(
		"use_email",
		(
			True,
			False,
		),
	)
	def test_raises_user_exists(
		self,
		use_email: bool,
		admin_user_client: APIClient,
		mocker: MockerFixture,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		m_data = {LOCAL_ATTR_USERNAME: "testuser"}
		if use_email:
			m_data[LOCAL_ATTR_EMAIL] = (
				f"testuser@{f_runtime_settings.LDAP_DOMAIN}"
			)

		m_ldap_user_exists = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_user_exists",
			side_effect=exc_ldap.LDAPObjectExists,
		)
		m_ldap_user_insert = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_user_insert",
		)
		m_ldap_set_password = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_set_password",
		)

		# Exec
		response: Response = admin_user_client.post(
			self.endpoint,
			data=m_data,
			format="json",
		)

		# Asserts
		assert response.status_code == status.HTTP_409_CONFLICT
		m_ldap_user_exists.assert_called_once_with(
			username="testuser",
			email=None
			if not use_email
			else m_data.get(f_runtime_settings.LDAP_FIELD_MAP["email"]),
		)
		m_ldap_user_insert.assert_not_called()
		m_ldap_set_password.assert_not_called()

	def test_raises_passwords_dont_match(
		self,
		admin_user_client: APIClient,
		mocker: MockerFixture,
	):
		m_data = {
			LOCAL_ATTR_USERNAME: "testuser",
			LOCAL_ATTR_PASSWORD: "1234",
			LOCAL_ATTR_PASSWORD_CONFIRM: "4321",
		}
		m_ldap_user_exists = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_user_exists",
		)
		m_ldap_user_insert = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_user_insert",
		)
		m_ldap_set_password = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_set_password",
		)

		# Exec
		response: Response = admin_user_client.post(
			self.endpoint,
			data=m_data,
			format="json",
		)

		# Asserts
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("errors")\
			.get(LOCAL_ATTR_PASSWORD_CONFIRM)[0] == "Passwords do not match"
		m_ldap_user_exists.assert_not_called()
		m_ldap_user_insert.assert_not_called()
		m_ldap_set_password.assert_not_called()

	def test_serializer_raises(
		self,
		admin_user_client: APIClient,
		mocker: MockerFixture,
	):
		m_data = {LOCAL_ATTR_USERNAME: "$#BADUSERNAME)\\"}
		m_ldap_user_exists = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_user_exists",
		)
		m_ldap_user_insert = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_user_insert",
		)
		m_ldap_set_password = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_set_password",
		)

		# Exec
		response: Response = admin_user_client.post(
			self.endpoint,
			data=m_data,
			format="json",
		)

		# Asserts
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("code") == "bad_request"
		m_ldap_user_exists.assert_not_called()
		m_ldap_user_insert.assert_not_called()
		m_ldap_set_password.assert_not_called()


class TestUpdate:
	endpoint = "/api/ldap/users/update/"

	def test_success(
		self,
		admin_user_client: APIClient,
		mocker: MockerFixture,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		m_perm_list = [
			LDAP_UF_DONT_EXPIRE_PASSWD,
			LDAP_UF_NORMAL_ACCOUNT,
		]
		m_data = {
			LOCAL_ATTR_USERNAME: "testuser",
			LOCAL_ATTR_PATH: "OU=mock ou,DC=example,DC=com",
			LOCAL_ATTR_EMAIL: f"testuser@{f_runtime_settings.LDAP_DOMAIN}",
			LOCAL_ATTR_FIRST_NAME: "Test",
			LOCAL_ATTR_LAST_NAME: "User",
			LOCAL_ATTR_PERMISSIONS: m_perm_list,
		}
		expected_m_data = m_data.copy()

		m_ldap_user_exists = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_user_exists",
			return_value=True,
		)
		m_ldap_user_update = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_update"
		)

		# Exec
		response: Response = admin_user_client.put(
			self.endpoint,
			data=m_data,
			format="json",
		)

		assert response.status_code == status.HTTP_200_OK
		m_ldap_user_exists.assert_any_call(
			username=m_data.get(LOCAL_ATTR_USERNAME),
			return_exception=False,
		)
		m_ldap_user_exists.assert_any_call(
			email=m_data.get(LOCAL_ATTR_EMAIL),
		)
		m_ldap_user_update.assert_called_once_with(data=expected_m_data)

	def test_raises_anti_lockout(
		self,
		admin_user: User,
		admin_user_client: APIClient,
		mocker: MockerFixture,
	):
		m_data = {
			LOCAL_ATTR_USERNAME: admin_user.username,
			LOCAL_ATTR_PERMISSIONS: [
				LDAP_UF_ACCOUNT_DISABLE,
				LDAP_UF_NORMAL_ACCOUNT,
			],
		}

		m_ldap_user_exists = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_user_exists",
		)
		m_ldap_user_update = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_update"
		)

		# Exec
		response: Response = admin_user_client.put(
			self.endpoint,
			data=m_data,
			format="json",
		)

		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("code") == "user_anti_lockout"
		m_ldap_user_exists.assert_not_called()
		m_ldap_user_update.assert_not_called()

	@pytest.mark.parametrize(
		"bad_key, bad_value",
		(
			(LOCAL_ATTR_PATH, "some_bad_dn"),
			(LOCAL_ATTR_PERMISSIONS, "some_bad_perm"),
		),
	)
	def test_raises_serializer_bad_request(
		self,
		bad_key: str,
		bad_value: str,
		admin_user_client: APIClient,
		mocker: MockerFixture,
	):
		m_data = {LOCAL_ATTR_USERNAME: "testuser"}
		m_data[bad_key] = bad_value
		expected_m_data = m_data.copy()
		expected_m_data.pop(LOCAL_ATTR_PATH, None)
		expected_m_data.pop(LOCAL_ATTR_PERMISSIONS, None)

		m_ldap_user_exists = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_user_exists",
		)
		m_ldap_user_update = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_update"
		)

		# Exec
		response: Response = admin_user_client.put(
			self.endpoint,
			data=m_data,
			format="json",
		)

		assert response.status_code == status.HTTP_400_BAD_REQUEST
		m_ldap_user_exists.assert_not_called()
		m_ldap_user_update.assert_not_called()

	def test_raises_user_does_not_exist(
		self,
		admin_user_client: APIClient,
		mocker: MockerFixture,
	):
		m_data = {
			LOCAL_ATTR_USERNAME: "testuser",
			LOCAL_ATTR_PATH: "OU=mock ou,DC=example,DC=com",
		}
		expected_m_data = m_data.copy()
		expected_m_data.pop(LOCAL_ATTR_PATH, None)
		expected_m_data.pop(LOCAL_ATTR_PERMISSIONS, None)

		m_ldap_user_exists = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_exists", return_value=False
		)
		m_ldap_user_update = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_update"
		)

		# Exec
		response: Response = admin_user_client.put(
			self.endpoint,
			data=m_data,
			format="json",
		)

		assert response.status_code == status.HTTP_404_NOT_FOUND
		m_ldap_user_exists.call_count == 1
		m_ldap_user_update.assert_not_called()


class TestChangeStatus:
	endpoint = "/api/ldap/users/change_status/"

	@pytest.mark.parametrize(
		"enabled",
		(
			True,
			False,
		),
	)
	def test_success(
		self,
		enabled: bool,
		admin_user_client: APIClient,
		mocker: MockerFixture,
	):
		m_ldap_user_exists = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_exists", return_value=True
		)
		m_change_status = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_change_status"
		)
		m_data = {LOCAL_ATTR_USERNAME: "someotheruser", "enabled": enabled}

		# Exec
		response: Response = admin_user_client.post(
			self.endpoint,
			data=m_data,
			format="json",
		)
		assert response.status_code == status.HTTP_200_OK
		m_change_status.assert_called_once_with(
			username=m_data[LOCAL_ATTR_USERNAME],
			enabled=enabled,
		)
		m_ldap_user_exists.assert_called_once_with(
			username=m_data[LOCAL_ATTR_USERNAME],
			return_exception=False,
		)

	@pytest.mark.parametrize(
		"delete_key",
		(
			LOCAL_ATTR_USERNAME,
			"enabled",
		),
	)
	def test_missing_key_raises(
		self,
		delete_key: str,
		admin_user_client: APIClient,
		mocker: MockerFixture,
	):
		m_change_status = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_change_status"
		)
		m_data = {LOCAL_ATTR_USERNAME: "testuser", "enabled": True}
		m_data.pop(delete_key, None)

		# Exec
		response: Response = admin_user_client.post(
			self.endpoint,
			data=m_data,
			format="json",
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		m_change_status.assert_not_called()

	def test_raises_anti_lockout(
		self,
		admin_user: User,
		admin_user_client: APIClient,
		mocker: MockerFixture,
	):
		m_change_status = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_change_status"
		)
		m_data = {LOCAL_ATTR_USERNAME: admin_user.username, "enabled": True}

		# Exec
		response: Response = admin_user_client.post(
			self.endpoint,
			data=m_data,
			format="json",
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("code") == "user_anti_lockout"
		m_change_status.assert_not_called()


class TestDelete:
	endpoint = "/api/ldap/users/delete/"

	@pytest.mark.django_db
	def test_success(
		self,
		user_factory,
		admin_user_client: APIClient,
		mocker: MockerFixture,
	):
		m_username = "someotheruser"
		m_user: User = user_factory(
			username=m_username,
			email=f"{m_username}@example.com",
			user_type=USER_TYPE_LDAP,
		)
		m_ldap_user_exists = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_exists", return_value=True
		)
		m_ldap_user_delete = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_delete"
		)

		# Exec
		response: Response = admin_user_client.post(
			self.endpoint,
			data={LOCAL_ATTR_USERNAME: m_username},
			format="json",
		)

		assert response.status_code == status.HTTP_200_OK
		assert not User.objects.filter(username=m_user.username).exists()
		m_ldap_user_exists.assert_called_once_with(
			username=m_user.username, return_exception=False
		)
		m_ldap_user_delete.assert_called_once_with(username=m_user.username)

	def test_raises_bad_request(
		self,
		admin_user_client: APIClient,
		mocker: MockerFixture,
	):
		m_ldap_user_exists = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_exists", return_value=True
		)
		m_ldap_user_delete = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_delete"
		)

		# Exec
		response: Response = admin_user_client.post(
			self.endpoint,
			data={},
			format="json",
		)

		assert response.status_code == status.HTTP_400_BAD_REQUEST
		m_ldap_user_exists.assert_not_called()
		m_ldap_user_delete.assert_not_called()

	def test_raises_anti_lockout(
		self,
		admin_user: User,
		admin_user_client: APIClient,
		mocker: MockerFixture,
	):
		m_ldap_user_exists = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_exists", return_value=True
		)
		m_ldap_user_delete = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_delete"
		)

		# Exec
		response: Response = admin_user_client.post(
			self.endpoint,
			data={LOCAL_ATTR_USERNAME: admin_user.username},
			format="json",
		)

		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("code") == "user_anti_lockout"
		m_ldap_user_exists.assert_not_called()
		m_ldap_user_delete.assert_not_called()


class TestChangePassword:
	endpoint = "/api/ldap/users/change_password/"

	@pytest.mark.parametrize(
		"m_data",
		(
			{},
			{LOCAL_ATTR_USERNAME: "testuser"},
			{
				LOCAL_ATTR_PASSWORD: "1234",
				LOCAL_ATTR_PASSWORD_CONFIRM: "4321",
			},
		),
	)
	def test_raises_bad_request(
		self,
		m_data: dict,
		user_factory,
		admin_user_client: APIClient,
		mocker: MockerFixture,
	):
		m_ldap_user_exists = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_exists", return_value=True
		)
		m_ldap_set_password = mocker.patch.object(
			LDAPUserViewSet, "ldap_set_password"
		)

		# Exec
		response: Response = admin_user_client.post(
			self.endpoint,
			data=m_data,
			format="json",
		)

		assert response.status_code == status.HTTP_400_BAD_REQUEST
		m_ldap_user_exists.assert_not_called()
		m_ldap_set_password.assert_not_called()

	def test_success(
		self,
		user_factory,
		admin_user: User,
		admin_user_client: APIClient,
		f_log_mixin: LogMixin,
		mocker: MockerFixture,
	):
		m_user: User = user_factory(
			username="someuser", email="someuser@example.com"
		)
		m_user_entry = mocker.Mock()
		m_user_entry.entry_dn = "mock_dn"
		m_password = "MockPassword"
		m_data = {
			LOCAL_ATTR_USERNAME: m_user.username,
			LOCAL_ATTR_PASSWORD: m_password,
			LOCAL_ATTR_PASSWORD_CONFIRM: m_password,
		}
		m_ldap_user_exists = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_exists", return_value=True
		)
		m_ldap_set_password = mocker.patch.object(
			LDAPUserViewSet, "ldap_set_password"
		)
		m_get_user_object = mocker.patch.object(
			LDAPUserViewSet, "get_user_object", return_value=m_user_entry
		)

		# Exec
		response: Response = admin_user_client.post(
			self.endpoint,
			data=m_data,
			format="json",
		)

		assert response.status_code == status.HTTP_200_OK
		m_ldap_user_exists.assert_called_once_with(
			username=m_data[LOCAL_ATTR_USERNAME],
			return_exception=False,
		)
		m_get_user_object.assert_called_once_with(username=m_data[LOCAL_ATTR_USERNAME])
		m_ldap_set_password.assert_called_once_with(
			user_dn=m_user_entry.entry_dn,
			user_pwd_new=m_data[LOCAL_ATTR_PASSWORD],
			set_by_admin=True,
		)
		f_log_mixin.log.assert_called_once_with(
			user=admin_user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=m_data[LOCAL_ATTR_USERNAME],
			message=LOG_EXTRA_USER_CHANGE_PASSWORD,
		)
		# User should have unusable password as it is LDAP Type
		assert not m_user.check_password(m_password)


class TestUnlock:
	endpoint = "/api/ldap/users/unlock/"

	def test_raises_bad_request(self, admin_user_client: APIClient):
		# Exec
		response: Response = admin_user_client.post(
			self.endpoint,
			data={},
			format="json",
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST

	def test_raises_user_does_not_exist(
		self,
		admin_user_client: APIClient,
		mocker: MockerFixture,
	):
		m_ldap_user_exists = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_exists", return_value=False
		)
		m_ldap_user_unlock = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_unlock"
		)

		# Exec
		response: Response = admin_user_client.post(
			self.endpoint,
			data={LOCAL_ATTR_USERNAME: "someuser"},
			format="json",
		)

		# Assertions
		assert response.status_code == status.HTTP_404_NOT_FOUND
		assert response.data.get("code") == "user_dn_does_not_exist"
		m_ldap_user_exists.assert_called_once_with(
			username="someuser",
			return_exception=False,
		)
		m_ldap_user_unlock.assert_not_called()

	def test_raises_could_not_unlock(
		self,
		admin_user_client: APIClient,
		f_ldap_connector: LDAPConnectorMock,
		mocker: MockerFixture,
	):
		f_ldap_connector.connection.result = {"description": "someError"}
		m_ldap_user_exists = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_exists", return_value=True
		)
		m_ldap_user_unlock = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_unlock"
		)

		# Exec
		response: Response = admin_user_client.post(
			self.endpoint,
			data={LOCAL_ATTR_USERNAME: "someuser"},
			format="json",
		)

		# Assertions
		assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
		assert response.data.get("code") == "user_unlock_error"
		m_ldap_user_exists.assert_called_once_with(
			username="someuser",
			return_exception=False,
		)
		m_ldap_user_unlock.assert_called_once_with(username="someuser")

	def test_success(
		self,
		admin_user_client: APIClient,
		f_ldap_connector: LDAPConnectorMock,
		mocker: MockerFixture,
	):
		f_ldap_connector.connection.result = {"description": "success"}
		m_ldap_user_exists = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_exists", return_value=True
		)
		m_ldap_user_unlock = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_unlock"
		)

		# Exec
		response: Response = admin_user_client.post(
			self.endpoint,
			data={LOCAL_ATTR_USERNAME: "someuser"},
			format="json",
		)

		# Assertions
		assert response.status_code == status.HTTP_200_OK
		m_ldap_user_exists.assert_called_once_with(
			username="someuser",
			return_exception=False,
		)
		m_ldap_user_unlock.assert_called_once_with(username="someuser")


@pytest.fixture
def f_bulk_insert_data(f_runtime_settings: RuntimeSettingsSingleton):
	result = {
		"headers":[
			LOCAL_ATTR_USERNAME,
			LOCAL_ATTR_EMAIL,
			LOCAL_ATTR_FIRST_NAME,
			LOCAL_ATTR_LAST_NAME,
		],
		"users":[
			# Should Succeed
			{
				LOCAL_ATTR_USERNAME: "testuser1",
				LOCAL_ATTR_EMAIL: f"testuser1@{f_runtime_settings.LDAP_DOMAIN}",
				LOCAL_ATTR_FIRST_NAME: "Test",
				LOCAL_ATTR_LAST_NAME: "User 1",
			},
			# Should Skip
			{
				LOCAL_ATTR_USERNAME: "testuser2",
				LOCAL_ATTR_EMAIL: f"testuser2@{f_runtime_settings.LDAP_DOMAIN}",
				LOCAL_ATTR_FIRST_NAME: "Test",
				LOCAL_ATTR_LAST_NAME: "User 2",
			},
			# Should Fail
			{
				LOCAL_ATTR_USERNAME: "testuser3",
				LOCAL_ATTR_EMAIL: f"testuser3@{f_runtime_settings.LDAP_DOMAIN}",
				LOCAL_ATTR_FIRST_NAME: "Test",
				LOCAL_ATTR_LAST_NAME: "User 3",
			},
			# Should import but fail password
			{
				LOCAL_ATTR_USERNAME: "testuser4",
				LOCAL_ATTR_EMAIL: f"testuser4@{f_runtime_settings.LDAP_DOMAIN}",
				LOCAL_ATTR_FIRST_NAME: "Test",
				LOCAL_ATTR_LAST_NAME: "User 4",
			},
		],
		LOCAL_ATTR_PATH: f"OU=Test,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}",
		"mapping":{
			h: h for h in (
				LOCAL_ATTR_USERNAME,
				LOCAL_ATTR_EMAIL,
				LOCAL_ATTR_FIRST_NAME,
				LOCAL_ATTR_LAST_NAME,
			)
		},
		"placeholder_password":"mock_password",
	}
	return result

class TestBulkInsert:
	endpoint = "/api/ldap/users/bulk_insert/"

	@pytest.mark.parametrize(
		"missing_key",
		(
			"headers",
			"users",
		),
		ids=[
			"Raises on missing headers key",
			"Raises on missing users key"
		]
	)
	def test_raises_missing_data_key(
		self,
		admin_user_client: APIClient,
		missing_key: str
	):
		bad_data = {
			"headers": "some_value",
			"users": "some_value",
		}
		bad_data.pop(missing_key)
		expected_code = status.HTTP_400_BAD_REQUEST
		expected_exc = "data_key_missing"
		response: Response = admin_user_client.post(
			self.endpoint,
			data=bad_data,
			format="json",
		)
		response_data: dict = response.data
		assert response.status_code == expected_code
		assert response_data.get("code") == expected_exc
		assert response_data.get("key") == missing_key

	def test_success(
		self,
		admin_user_client: APIClient,
		f_bulk_insert_data: dict,
		mocker: MockerFixture,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		m_expected_exclude_keys = (
			LOCAL_ATTR_DN,  # We don't want any front-end generated DN
			LOCAL_ATTR_DN_SHORT,  # We don't want any front-end generated DN
		)
		_pop_keys = (
			"exists",
			"fails_insert",
			"fails_password",
		)
		m_users: list[dict] = f_bulk_insert_data.get("users")
		m_users[1]["exists"] = True
		m_users[2]["fails_insert"] = True
		m_users[3]["fails_password"] = True
		m_users.append(
			# Should fail serialization
			{
				LOCAL_ATTR_USERNAME: False,
				LOCAL_ATTR_EMAIL: b"some_bytes",
				LOCAL_ATTR_FIRST_NAME: "Test",
				LOCAL_ATTR_LAST_NAME: "User 4",
			},
		)
		exists_results = [ u.get("exists", False) for u in m_users ]
		m_exists = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_user_exists",
			side_effect=tuple(exists_results),
		)
		insert_results = []
		for u in m_users:
			if u.get("exists", False): continue
			if not u.get("fails_insert", False):
				insert_results.append(
					"CN=%s,%s" % (
						u.get(LOCAL_ATTR_USERNAME),
						f_bulk_insert_data.get(LOCAL_ATTR_PATH),
					)
				)
			else:
				insert_results.append(None)
		m_insert = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_user_insert",
			side_effect=tuple(insert_results)
		)
		password_results = []
		for u in m_users:
			if u.get("exists", False): continue
			if u.get("fails_insert", False): continue
			if not u.get("fails_password", False):
				password_results.append(None)
			else:
				password_results.append(Exception)
		m_set_password = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_set_password",
			side_effect=tuple(password_results)
		)
		for _k in _pop_keys:
			for u in m_users:
				if _k in u:
					del u[_k]

		response: Response = admin_user_client.post(
			self.endpoint,
			data=f_bulk_insert_data,
			format="json",
		)
		response_data: dict = response.data

		# Assertions
		assert response.status_code == status.HTTP_200_OK
		imported_users = response_data.get("imported_users")
		skipped_users = response_data.get("skipped_users")
		failed_users = response_data.get("failed_users")

		assert len(imported_users) == 2
		assert "testuser1" in imported_users
		m_exists.assert_any_call(
			username=m_users[0][LOCAL_ATTR_USERNAME],
			email=m_users[0][LOCAL_ATTR_EMAIL],
			return_exception=False,
		)
		m_insert.assert_any_call(
			data=m_users[0] | {
				LOCAL_ATTR_PATH: f"OU=Test,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}",
				LOCAL_ATTR_PERMISSIONS: [LDAP_UF_NORMAL_ACCOUNT]
			},
			exclude_keys=m_expected_exclude_keys,
			return_exception=False,
		)
		m_set_password.assert_any_call(
			user_dn=insert_results[0],
			user_pwd_new=f_bulk_insert_data["placeholder_password"],
			set_by_admin=True,
		)
		assert "testuser4" in imported_users
		m_exists.assert_any_call(
			username=m_users[3][LOCAL_ATTR_USERNAME],
			email=m_users[3][LOCAL_ATTR_EMAIL],
			return_exception=False,
		)
		m_insert.assert_any_call(
			data=m_users[3] | {
				LOCAL_ATTR_PATH: f"OU=Test,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}",
				LOCAL_ATTR_PERMISSIONS: [LDAP_UF_NORMAL_ACCOUNT]
			},
			exclude_keys=m_expected_exclude_keys,
			return_exception=False,
		)
		m_set_password.call_count == 1

		assert len(skipped_users) == 1
		assert "testuser2" in skipped_users

		assert len(failed_users) == 3
		assert failed_users[0][LOCAL_ATTR_USERNAME] == "testuser3"
		assert failed_users[0]["stage"] == "insert"
		assert failed_users[1][LOCAL_ATTR_USERNAME] == "testuser4"
		assert failed_users[1]["stage"] == "password"
		assert failed_users[2][LOCAL_ATTR_USERNAME] == "unknown"
		assert failed_users[2]["stage"] == "serializer_validation"

	def test_success_no_password(
		self,
		admin_user_client: APIClient,
		f_bulk_insert_data: dict,
		mocker: MockerFixture,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		f_bulk_insert_data.pop("placeholder_password", None)
		m_expected_exclude_keys = (
			LOCAL_ATTR_DN,  # We don't want any front-end generated DN
			LOCAL_ATTR_DN_SHORT,  # We don't want any front-end generated DN
		)
		m_users: list[dict] = f_bulk_insert_data.get("users")
		f_bulk_insert_data["users"] = [m_users[0]]
		m_exists = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_user_exists",
			return_value=False
		)
		m_insert = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_user_insert",
			return_value="CN=%s,%s" % (
				m_users[0].get(LOCAL_ATTR_USERNAME),
				f_bulk_insert_data.get(LOCAL_ATTR_PATH),
			)
		)
		m_set_password = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_set_password",
			return_value=None
		)

		response: Response = admin_user_client.post(
			self.endpoint,
			data=f_bulk_insert_data,
			format="json",
		)
		response_data: dict = response.data

		# Assertions
		assert response.status_code == status.HTTP_200_OK
		imported_users = response_data.get("imported_users")

		assert len(imported_users) == 1
		assert "testuser1" in imported_users
		m_exists.assert_any_call(
			username=m_users[0][LOCAL_ATTR_USERNAME],
			email=m_users[0][LOCAL_ATTR_EMAIL],
			return_exception=False,
		)
		m_insert.assert_any_call(
			data=m_users[0] | {
				LOCAL_ATTR_PATH: f"OU=Test,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}",
				LOCAL_ATTR_PERMISSIONS: [LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_ACCOUNT_DISABLE]
			},
			exclude_keys=m_expected_exclude_keys,
			return_exception=False,
		)
		m_set_password.assert_not_called()

	def test_with_mapping(
		self,
		admin_user_client: APIClient,
		f_bulk_insert_data: dict,
		mocker: MockerFixture,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		f_bulk_insert_data["mapping"] = {
			LOCAL_ATTR_USERNAME: "mock_user_fld",
			LOCAL_ATTR_EMAIL: "mock_email_fld",
			LOCAL_ATTR_FIRST_NAME: "mock_fname_fld",
			LOCAL_ATTR_LAST_NAME: "mock_lname_fld",
		}
		f_bulk_insert_data.pop("placeholder_password", None)
		m_expected_exclude_keys = (
			LOCAL_ATTR_DN,  # We don't want any front-end generated DN
			LOCAL_ATTR_DN_SHORT,  # We don't want any front-end generated DN
		)
		m_users: list[dict] = f_bulk_insert_data.get("users")
		m_expected_user_dict = m_users[0].copy()
		f_bulk_insert_data["users"] = [
			{
				"mock_user_fld": m_expected_user_dict[LOCAL_ATTR_USERNAME],
				"mock_email_fld": m_expected_user_dict[LOCAL_ATTR_EMAIL],
				"mock_fname_fld": m_expected_user_dict[LOCAL_ATTR_FIRST_NAME],
				"mock_lname_fld": m_expected_user_dict[LOCAL_ATTR_LAST_NAME],
			}
		]
		m_exists = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_user_exists",
			return_value=False
		)
		m_insert = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_user_insert",
			return_value="CN=%s,%s" % (
				m_expected_user_dict[LOCAL_ATTR_USERNAME],
				f_bulk_insert_data.get(LOCAL_ATTR_PATH),
			)
		)
		m_set_password = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_set_password",
			return_value=None
		)

		response: Response = admin_user_client.post(
			self.endpoint,
			data=f_bulk_insert_data,
			format="json",
		)
		response_data: dict = response.data

		# Assertions
		assert response.status_code == status.HTTP_200_OK
		imported_users = response_data.get("imported_users")

		assert len(imported_users) == 1
		assert "testuser1" in imported_users
		m_exists.assert_any_call(
			username=m_expected_user_dict[LOCAL_ATTR_USERNAME],
			email=m_expected_user_dict[LOCAL_ATTR_EMAIL],
			return_exception=False,
		)
		m_insert.assert_any_call(
			data=m_expected_user_dict | {
				LOCAL_ATTR_PATH: f"OU=Test,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}",
				LOCAL_ATTR_PERMISSIONS: [LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_ACCOUNT_DISABLE]
			},
			exclude_keys=m_expected_exclude_keys,
			return_exception=False,
		)
		m_set_password.assert_not_called()
	
	def test_with_per_user_password(
		self,
		admin_user_client: APIClient,
		f_bulk_insert_data: dict,
		mocker: MockerFixture,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		f_bulk_insert_data.pop("placeholder_password", None)
		f_bulk_insert_data["headers"] = f_bulk_insert_data["headers"] + [LOCAL_ATTR_PASSWORD]
		m_expected_exclude_keys = (
			LOCAL_ATTR_PASSWORD,
			LOCAL_ATTR_DN,  # We don't want any front-end generated DN
			LOCAL_ATTR_DN_SHORT,  # We don't want any front-end generated DN
		)
		m_users: list[dict] = [f_bulk_insert_data.get("users")[0]]
		m_user_password = "mock_user_password"
		m_users[0][LOCAL_ATTR_PASSWORD] = m_user_password
		f_bulk_insert_data["users"] = m_users

		m_exists = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_user_exists",
			return_value=False
		)
		m_user_dn = "CN=%s,%s" % (
			m_users[0][LOCAL_ATTR_USERNAME],
			f_bulk_insert_data.get(LOCAL_ATTR_PATH),
		)
		m_insert = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_user_insert",
			return_value=m_user_dn
		)
		m_set_password = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_set_password",
			return_value=None
		)

		response: Response = admin_user_client.post(
			self.endpoint,
			data=f_bulk_insert_data,
			format="json",
		)
		response_data: dict = response.data

		# Assertions
		assert response.status_code == status.HTTP_200_OK
		imported_users = response_data.get("imported_users")

		assert len(imported_users) == 1
		assert "testuser1" in imported_users
		m_exists.assert_any_call(
			username=m_users[0][LOCAL_ATTR_USERNAME],
			email=m_users[0][LOCAL_ATTR_EMAIL],
			return_exception=False,
		)
		expected_user_data = m_users[0] | {
			LOCAL_ATTR_PATH: f"OU=Test,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}",
			LOCAL_ATTR_PERMISSIONS: [LDAP_UF_NORMAL_ACCOUNT]
		}
		del expected_user_data[LOCAL_ATTR_PASSWORD]
		m_insert.assert_any_call(
			data=expected_user_data,
			exclude_keys=m_expected_exclude_keys,
			return_exception=False,
		)
		m_set_password.assert_called_once_with(
			user_dn=m_user_dn,
			user_pwd_new=m_user_password,
			set_by_admin=True,
		)

@pytest.fixture
def f_bulk_update_data():
	return {
		"users":["testuser1", "testuser2"],
		LOCAL_ATTR_PERMISSIONS: [LDAP_UF_NORMAL_ACCOUNT],
		"values":{
			LOCAL_ATTR_COUNTRY: "Argentina",
		}
	}

class TestBulkUpdate:
	endpoint = "/api/ldap/users/bulk_update/"

	def test_success(
		self,
		admin_user_client: APIClient,
		f_bulk_update_data: dict,
		mocker: MockerFixture,
	):
		expected_user_count = len(f_bulk_update_data["users"])
		m_exists = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_exists", return_value=True)
		m_update = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_update", return_value=True)
		response: Response = admin_user_client.post(
			self.endpoint,
			data=f_bulk_update_data,
			format="json",
		)
		response_data: dict = response.data

		assert response.status_code == status.HTTP_200_OK
		assert len(response_data.get("updated_users")) == expected_user_count
		assert m_exists.call_count == expected_user_count
		assert m_update.call_count == expected_user_count
		for u in f_bulk_update_data["users"]:
			m_exists.assert_any_call(
				username=u,
				return_exception=False,
			)
			m_update.assert_any_call(data={
				LOCAL_ATTR_USERNAME: u,
				LOCAL_ATTR_PERMISSIONS: f_bulk_update_data[LOCAL_ATTR_PERMISSIONS],
				LOCAL_ATTR_COUNTRY: "Argentina",
			})

	def test_not_exists_raises(
		self,
		admin_user_client: APIClient,
		f_bulk_update_data: dict,
		mocker: MockerFixture,
	):
		m_exists = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_exists", return_value=False)
		m_update = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_update", return_value=None)
		response: Response = admin_user_client.post(
			self.endpoint,
			data=f_bulk_update_data,
			format="json",
		)

		assert response.status_code == status.HTTP_404_NOT_FOUND
		m_exists.assert_called_once()
		m_update.assert_not_called()

	def test_serializer_failure(
		self,
		admin_user_client: APIClient,
		f_bulk_update_data: dict,
		mocker: MockerFixture,
	):
		user_count = len(f_bulk_update_data["users"])
		f_bulk_update_data["values"] = {
			LOCAL_ATTR_COUNTRY: "Some Inexistent Country"
		}
		m_exists = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_exists", return_value=True)
		m_update = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_update", return_value=None)
		response: Response = admin_user_client.post(
			self.endpoint,
			data=f_bulk_update_data,
			format="json",
		)
		response_data: dict = response.data

		assert response.status_code == status.HTTP_200_OK
		m_exists.call_count == user_count
		failed_users = response_data["failed_users"]
		assert len(failed_users) == user_count
		m_update.assert_not_called()
		for error_detail in failed_users:
			assert error_detail["stage"] == "serializer_validation"

	def test_update_failure(
		self,
		admin_user_client: APIClient,
		f_bulk_update_data: dict,
		mocker: MockerFixture,
	):
		user_count = len(f_bulk_update_data["users"])
		m_exists = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_exists", return_value=True)
		m_update = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_update", side_effect=Exception)
		response: Response = admin_user_client.post(
			self.endpoint,
			data=f_bulk_update_data,
			format="json",
		)
		response_data: dict = response.data

		assert response.status_code == status.HTTP_200_OK
		m_exists.call_count == user_count
		failed_users = response_data["failed_users"]
		assert len(failed_users) == user_count
		m_update.call_count == user_count
		for error_detail in failed_users:
			assert error_detail["stage"] == "update"

	def test_bad_request_raises(
		self,
		admin_user_client: APIClient,
		f_bulk_update_data: dict,
		mocker: MockerFixture,
	):
		f_bulk_update_data.pop("values")
		f_bulk_update_data.pop(LOCAL_ATTR_PERMISSIONS)
		m_exists = mocker.patch.object(LDAPUserViewSet, "ldap_user_exists")
		m_update = mocker.patch.object(LDAPUserViewSet, "ldap_user_update")
		response: Response = admin_user_client.post(
			self.endpoint,
			data=f_bulk_update_data,
			format="json",
		)

		assert response.status_code == status.HTTP_400_BAD_REQUEST
		m_exists.assert_not_called()
		m_update.assert_not_called()

@pytest.fixture
def f_bulk_change_status_data():
	return {
		"users":[
			{LOCAL_ATTR_USERNAME:"testuser1"},
			{LOCAL_ATTR_USERNAME:"testuser2"},
		],
		"disable": False
	}

class TestBulkChangeStatus:
	endpoint = "/api/ldap/users/bulk_change_status/"

	@pytest.mark.parametrize(
		"flatten_users, disable, expected",
		(
			(False, True, False,),
			(False, False, True,),
			(True, True, False,),
			(True, False, True,),
		),
		ids=[
			"User dict list, disable is True, expects enable False",
			"User dict list, disable is False, expects enable True",
			"Username list, disable is True, expects enable False",
			"Username list, disable is False, expects enable True",
		]
	)
	def test_success(
		self,
		flatten_users: bool,
		disable: bool,
		expected: bool,
		admin_user_client: APIClient,
		f_logger: Logger,
		f_bulk_change_status_data: dict,
		mocker: MockerFixture,
	):
		if flatten_users:
			f_bulk_change_status_data["users"] = [
				u.get(LOCAL_ATTR_USERNAME) for u in f_bulk_change_status_data["users"]
			]
		f_bulk_change_status_data["disable"] = disable
		user_count = len(f_bulk_change_status_data["users"])
		m_change_status = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_user_change_status",
			side_effect=(
				None,
				Exception,
			)
		)
		response: Response = admin_user_client.post(
			self.endpoint,
			data=f_bulk_change_status_data,
			format="json",
		)
		response_data: dict = response.data

		assert len(response_data["data"]) == 1
		m_change_status.call_count == user_count
		f_logger.error.assert_called_once()
		for u in f_bulk_change_status_data["users"]:
			m_change_status.assert_any_call(
				username=u[LOCAL_ATTR_USERNAME] if not flatten_users else u,
				enabled=expected,
			)

	def test_raises_bad_request_no_disable_key(
		self,
		admin_user_client: APIClient,
		f_bulk_change_status_data: dict,
		mocker: MockerFixture,
	):
		del f_bulk_change_status_data["disable"]
		m_change_status = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_change_status")
		response: Response = admin_user_client.post(
			self.endpoint,
			data=f_bulk_change_status_data,
			format="json",
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		m_change_status.assert_not_called()

	@pytest.mark.parametrize(
		"users",
		(
			[],
			[False],
			{"users":[]},
		),
	)
	def test_raises_bad_request_users_not_list(
		self,
		users,
		admin_user_client: APIClient,
		f_bulk_change_status_data: dict,
		mocker: MockerFixture,
	):
		f_bulk_change_status_data["users"] = users
		m_change_status = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_change_status")
		response: Response = admin_user_client.post(
			self.endpoint,
			data=f_bulk_change_status_data,
			format="json",
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		m_change_status.assert_not_called()

@pytest.fixture
def f_bulk_delete_data():
	return [
		{LOCAL_ATTR_USERNAME:"testuser1"},
		{LOCAL_ATTR_USERNAME:"testuser2"},
	]

class TestBulkDelete:
	endpoint = "/api/ldap/users/bulk_delete/"

	@pytest.mark.parametrize(
		"flatten_users",
		(
			True,
			False,
		),
	)
	def test_success(
		self,
		flatten_users: bool,
		f_bulk_delete_data: list[dict, str],
		admin_user_client: APIClient,
		mocker: MockerFixture
	):
		flattened_users = [
			u.get(LOCAL_ATTR_USERNAME) for u in f_bulk_delete_data
		]
		m_delete = mocker.patch.object(LDAPUserViewSet, "ldap_user_delete")
		response: Response = admin_user_client.post(
			self.endpoint,
			data=f_bulk_delete_data if not flatten_users else flattened_users,
			format="json",
		)
		assert response.status_code == status.HTTP_200_OK
		assert response.data.get("data") == flattened_users
		m_delete.call_count == len(flattened_users)
		for u in f_bulk_delete_data:
			m_delete.assert_any_call(
				username=u.get(LOCAL_ATTR_USERNAME)
			)

class TestBulkUnlock:
	endpoint = "/api/ldap/users/bulk_unlock/"

	@pytest.mark.parametrize(
		"flatten_users",
		(
			True,
			False,
		),
	)
	def test_success(
		self,
		flatten_users: bool,
		f_bulk_delete_data: list[dict, str],
		f_ldap_connector: LDAPConnectorMock,
		admin_user_client: APIClient,
		mocker: MockerFixture
	):
		m_ldap_result = {"description": "success"}
		f_ldap_connector.connection.result = m_ldap_result
		flattened_users = [
			u.get(LOCAL_ATTR_USERNAME) for u in f_bulk_delete_data
		]
		m_unlock = mocker.patch.object(LDAPUserViewSet, "ldap_user_unlock")
		response: Response = admin_user_client.post(
			self.endpoint,
			data=f_bulk_delete_data if not flatten_users else flattened_users,
			format="json",
		)
		assert response.status_code == status.HTTP_200_OK
		assert response.data.get("data") == flattened_users
		m_unlock.call_count == len(flattened_users)
		for u in f_bulk_delete_data:
			m_unlock.assert_any_call(
				username=u.get(LOCAL_ATTR_USERNAME)
			)

	def test_unhandled_error(
		self,
		f_bulk_delete_data: list[dict, str],
		f_ldap_connector: LDAPConnectorMock,
		admin_user_client: APIClient,
		mocker: MockerFixture,
	):
		m_ldap_result = {"description": "error"}
		f_ldap_connector.connection.result = m_ldap_result
		m_unlock = mocker.patch.object(LDAPUserViewSet, "ldap_user_unlock")
		response: Response = admin_user_client.post(
			self.endpoint,
			data=f_bulk_delete_data,
			format="json",
		)
		assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
		m_unlock.call_count == len(f_bulk_delete_data)

class TestSelfChangePassword:
	endpoint = "/api/ldap/users/self_change_password/"

	def test_raises_not_ldap_user(self, normal_user_client: APIClient):
		response: Response = normal_user_client.post(
			self.endpoint,
			data={},
			format="json",
		)
		assert response.status_code == status.HTTP_406_NOT_ACCEPTABLE
		assert response.data.get("code") == "user_not_ldap_type"

	@pytest.mark.parametrize(
		"bad_data",
		(
			{
				LOCAL_ATTR_USERNAME: "some_other_username",
				LOCAL_ATTR_PASSWORD: "mock_password",
				LOCAL_ATTR_PASSWORD_CONFIRM: "mock_password",
			},
			{
				LOCAL_ATTR_DN: "some_dn",
				LOCAL_ATTR_PASSWORD: "mock_password",
				LOCAL_ATTR_PASSWORD_CONFIRM: "mock_password",
			},
		),
	)
	def test_raises_bad_request(
		self,
		bad_data,
		f_logger: Logger,
		normal_user: User,
		normal_user_client: APIClient,
	):
		# Mock local django user data
		normal_user.user_type = USER_TYPE_LDAP
		normal_user.save()

		response: Response = normal_user_client.post(
			self.endpoint,
			data=bad_data,
			format="json",
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		f_logger.warning.assert_called_once()

	@pytest.mark.parametrize(
		"bad_data, expected_exc",
		(
			({
				LOCAL_ATTR_PASSWORD: False,
				LOCAL_ATTR_PASSWORD_CONFIRM: "mock_password",
			}, "Not a valid string"),
			({
				LOCAL_ATTR_PASSWORD: "mock_password",
				LOCAL_ATTR_PASSWORD_CONFIRM: None,
			}, "may not be null"),
			({
				LOCAL_ATTR_PASSWORD: "some_mock_password",
				LOCAL_ATTR_PASSWORD_CONFIRM: "mock_password_does_not_match",
			}, "Passwords do not match"),
		),
	)
	def test_raises_serializer_invalid(
		self,
		bad_data: dict,
		expected_exc: str,
		normal_user: User,
		normal_user_client: APIClient,
	):
		# Mock local django user data
		normal_user.user_type = USER_TYPE_LDAP
		normal_user.save()

		response: Response = normal_user_client.post(
			self.endpoint,
			data=bad_data,
			format="json",
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert any(expected_exc in str(x) for x in response.data.values())

	def test_raises_user_not_exists(
		self,
		f_log_mixin: LogMixin,
		f_ldap_connector: LDAPConnectorMock,
		f_runtime_settings: RuntimeSettingsSingleton,
		normal_user: User,
		normal_user_client: APIClient,
		mocker: MockerFixture,
	):
		# Mock local django user data
		normal_user.user_type = USER_TYPE_LDAP
		normal_user.save()

		# Mock LDAPUser Instance and Class
		m_ldap_user = mocker.Mock(name="m_ldap_user")
		m_ldap_user.distinguished_name = normal_user.distinguished_name
		m_ldap_user.exists = False
		m_ldap_user.can_change_password = True
		m_ldap_user_cls = mocker.patch(
			"core.views.ldap.user.LDAPUser",
			return_value=m_ldap_user
		)
		# Mock set password method
		m_set_password = mocker.patch.object(
			LDAPUserViewSet, "ldap_set_password")

		# Execution
		response: Response = normal_user_client.post(
			self.endpoint,
			data={
				LOCAL_ATTR_PASSWORD: "mock_password",
				LOCAL_ATTR_PASSWORD_CONFIRM: "mock_password",
			},
			format="json",
		)

		# Assertions
		assert response.status_code == status.HTTP_404_NOT_FOUND
		m_ldap_user_cls.assert_called_once_with(
			connection=f_ldap_connector.connection,
			username=normal_user.username,
			search_attrs=[
				f_runtime_settings.LDAP_FIELD_MAP[LOCAL_ATTR_USERNAME],
				f_runtime_settings.LDAP_FIELD_MAP[LOCAL_ATTR_DN],
				f_runtime_settings.LDAP_FIELD_MAP[LOCAL_ATTR_UAC],
			]
		)
		m_set_password.assert_not_called()
		f_log_mixin.log.assert_not_called()

	def test_raises_user_cannot_change_pwd(
		self,
		f_log_mixin: LogMixin,
		f_ldap_connector: LDAPConnectorMock,
		f_runtime_settings: RuntimeSettingsSingleton,
		normal_user: User,
		normal_user_client: APIClient,
		mocker: MockerFixture,
	):
		# Mock local django user data
		normal_user.user_type = USER_TYPE_LDAP
		normal_user.save()

		# Mock LDAPUser Instance and Class
		m_ldap_user = mocker.Mock(name="m_ldap_user")
		m_ldap_user.distinguished_name = normal_user.distinguished_name
		m_ldap_user.exists = True
		m_ldap_user.can_change_password = False
		m_ldap_user_cls = mocker.patch(
			"core.views.ldap.user.LDAPUser",
			return_value=m_ldap_user
		)
		# Mock set password method
		m_set_password = mocker.patch.object(
			LDAPUserViewSet, "ldap_set_password")

		# Execution
		response: Response = normal_user_client.post(
			self.endpoint,
			data={
				LOCAL_ATTR_PASSWORD: "mock_password",
				LOCAL_ATTR_PASSWORD_CONFIRM: "mock_password",
			},
			format="json",
		)

		# Assertions
		assert response.status_code == status.HTTP_403_FORBIDDEN
		m_ldap_user_cls.assert_called_once_with(
			connection=f_ldap_connector.connection,
			username=normal_user.username,
			search_attrs=[
				f_runtime_settings.LDAP_FIELD_MAP[LOCAL_ATTR_USERNAME],
				f_runtime_settings.LDAP_FIELD_MAP[LOCAL_ATTR_DN],
				f_runtime_settings.LDAP_FIELD_MAP[LOCAL_ATTR_UAC],
			]
		)
		m_set_password.assert_not_called()
		f_log_mixin.log.assert_not_called()

	def test_success(
		self,
		f_log_mixin: LogMixin,
		f_ldap_connector: LDAPConnectorMock,
		f_runtime_settings: RuntimeSettingsSingleton,
		normal_user: User,
		normal_user_client: APIClient,
		mocker: MockerFixture,
	):
		# Mock local django user data
		normal_user.user_type = USER_TYPE_LDAP
		normal_user.distinguished_name = "CN=%s,CN=Users,%s" % (
			normal_user.username,
			f_runtime_settings.LDAP_AUTH_SEARCH_BASE,
		)
		# Mock saved LDAP user password in DB
		encrypted_data = aes_encrypt("mock_password_old")
		for index, field in enumerate(USER_PASSWORD_FIELDS):
			setattr(normal_user, field, encrypted_data[index])
		normal_user.save()
		normal_user.refresh_from_db()

		# Mock LDAPUser Instance and Class
		m_ldap_user = mocker.Mock(name="m_ldap_user")
		m_ldap_user.distinguished_name = normal_user.distinguished_name
		m_ldap_user.exists = True
		m_ldap_user.can_change_password = True
		m_ldap_user_cls = mocker.patch(
			"core.views.ldap.user.LDAPUser",
			return_value=m_ldap_user
		)
		# Mock set password method
		m_set_password = mocker.patch.object(
			LDAPUserViewSet, "ldap_set_password")

		# Execution
		response: Response = normal_user_client.post(
			self.endpoint,
			data={
				LOCAL_ATTR_PASSWORD: "mock_password",
				LOCAL_ATTR_PASSWORD_CONFIRM: "mock_password",
			},
			format="json",
		)

		# Assertions
		assert response.status_code == status.HTTP_200_OK
		m_ldap_user_cls.assert_called_once_with(
			connection=f_ldap_connector.connection,
			username=normal_user.username,
			search_attrs=[
				f_runtime_settings.LDAP_FIELD_MAP[LOCAL_ATTR_USERNAME],
				f_runtime_settings.LDAP_FIELD_MAP[LOCAL_ATTR_DN],
				f_runtime_settings.LDAP_FIELD_MAP[LOCAL_ATTR_UAC],
			]
		)
		m_set_password.assert_called_once_with(
			user_dn=normal_user.distinguished_name,
			user_pwd_new="mock_password",
			user_pwd_old="mock_password_old",
		)
		normal_user.refresh_from_db()
		assert aes_decrypt(*normal_user.encrypted_password) == "mock_password"
		f_log_mixin.log.assert_called_once_with(
			user=normal_user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=normal_user.username,
			message=LOG_EXTRA_USER_CHANGE_PASSWORD,
		)

class TestSelfUpdate:
	endpoint = "/api/ldap/users/self_update/"

	def test_raises_not_ldap_user(self, normal_user_client: APIClient):
		response: Response = normal_user_client.post(
			self.endpoint,
			data={},
			format="json",
		)
		assert response.status_code == status.HTTP_406_NOT_ACCEPTABLE
		assert response.data.get("code") == "user_not_ldap_type"

	@pytest.mark.parametrize(
		"bad_data",
		(
			{
				LOCAL_ATTR_USERNAME: "some_other_username",
				LOCAL_ATTR_COUNTRY: "Some Country"
			},
			{
				LOCAL_ATTR_DN: "some_dn",
				LOCAL_ATTR_COUNTRY: "Some Country"
			},
		),
	)
	def test_raises_bad_request(
		self,
		bad_data,
		f_logger: Logger,
		normal_user: User,
		normal_user_client: APIClient,
	):
		# Mock local django user data
		normal_user.user_type = USER_TYPE_LDAP
		normal_user.save()

		response: Response = normal_user_client.post(
			self.endpoint,
			data=bad_data,
			format="json",
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		f_logger.warning.assert_called_once()

	def test_success(
		self,
		f_logger: Logger,
		normal_user: User,
		normal_user_client: APIClient,
		mocker: MockerFixture,
	):
		m_email = "testchange@example.org"
		m_data = {
			LOCAL_ATTR_EMAIL: m_email,
			LOCAL_ATTR_COUNTRY: "Argentina",
			LOCAL_ATTR_ADDRESS: "Some Address",
			LOCAL_ATTR_IS_ENABLED: True,
			LOCAL_ATTR_UAC: 1234,
			LOCAL_ATTR_PERMISSIONS: [LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_ACCOUNT_DISABLE]
		}
		m_ldap_user_update = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_update")

		# Mock local django user data
		normal_user.user_type = USER_TYPE_LDAP
		normal_user.save()

		response: Response = normal_user_client.post(
			self.endpoint,
			data=m_data,
			format="json",
		)

		# Assertions
		assert response.status_code == status.HTTP_200_OK
		expected_data = m_data.copy()
		for key in (LOCAL_ATTR_IS_ENABLED, LOCAL_ATTR_UAC, LOCAL_ATTR_PERMISSIONS):
			expected_data.pop(key, None)
		m_ldap_user_update.assert_called_once_with(
			username=normal_user.username,
			user_data=expected_data,
		)
		normal_user.refresh_from_db()
		normal_user.email == m_email

class TestSelfInfo:
	endpoint = "/api/ldap/users/self_info/"

	@pytest.mark.parametrize(
		"user_prefix, expects_admin",
		(
			("normal", False),
			("admin", True),
		),
	)
	def test_success(
		self,
		user_prefix: str,
		expects_admin: bool,
		request: FixtureRequest,
	):
		_user: User = request.getfixturevalue(user_prefix + "_user")
		_api_client: APIClient = request.getfixturevalue(
			user_prefix + "_user_client"
		)
		_user.first_name = "Test"
		_user.last_name = "User"
		_user.email = "email@example.com"
		_user.save()
		_user.refresh_from_db()

		response: Response = _api_client.get(self.endpoint)
		data: dict = response.data.get("user")
		assert response.status_code == status.HTTP_200_OK
		_ATTRS_TO_CHECK = (
			LOCAL_ATTR_USERNAME,
			LOCAL_ATTR_FIRST_NAME,
			LOCAL_ATTR_LAST_NAME,
			LOCAL_ATTR_EMAIL,
		)
		for attr in _ATTRS_TO_CHECK:
			assert data.get(attr) == getattr(_user, attr)
		assert data.get("admin_allowed", False) == expects_admin


class TestSelfFetch:
	endpoint = "/api/ldap/users/self_fetch/"
