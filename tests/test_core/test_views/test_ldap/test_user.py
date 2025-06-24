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
from core.models.ldap_user import DEFAULT_LOCAL_ATTRS
from tests.test_core.conftest import RuntimeSettingsFactory
from tests.test_core.test_views.conftest import BaseViewTestClass
from datetime import datetime
from django.utils.timezone import now as tz_aware_now
from logging import Logger
from core.ldap.adsi import (
	LDAP_UF_DONT_EXPIRE_PASSWD,
	LDAP_UF_ACCOUNT_DISABLE,
	LDAP_UF_NORMAL_ACCOUNT,
)
from core.models.user import (
	User,
	USER_TYPE_LDAP,
	USER_TYPE_LOCAL,
	USER_PASSWORD_FIELDS,
)
from core.exceptions import ldap as exc_ldap
from core.constants.attrs.local import *
from core.constants.user import LOCAL_PUBLIC_FIELDS
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
		"core.views.ldap.user.logger", mocker.Mock(name="m_logger")
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


class TestList(BaseViewTestClass):
	_endpoint = "ldap/users-list"

	def test_list_users_success(
		self,
		admin_user_client: APIClient,
		mocker: MockerFixture,
	):
		"""Test successful user listing"""
		# Mock LDAP connection and data
		m_ldap_users = {
			"users": [
				{LOCAL_ATTR_USERNAME: "testuser", LOCAL_ATTR_IS_ENABLED: True},
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


class TestRetrieve(BaseViewTestClass):
	_endpoint = "ldap/users-retrieve"

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


class TestInsert(BaseViewTestClass):
	_endpoint = "ldap/users-list"

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
		m_ldap_user_insert.assert_called_once_with(data=expected_m_data_call)

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
		assert (
			response.data.get("errors").get(LOCAL_ATTR_PASSWORD_CONFIRM)[0]
			== "Passwords do not match"
		)
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


class TestUpdate(BaseViewTestClass):
	_endpoint = "ldap/users-list"

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


class TestChangeStatus(BaseViewTestClass):
	_endpoint = "ldap/users-change-status"

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


class TestDestroy(BaseViewTestClass):
	_endpoint = "ldap/users"

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
		response: Response = admin_user_client.patch(
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
		response: Response = admin_user_client.patch(
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
		response: Response = admin_user_client.patch(
			self.endpoint,
			data={LOCAL_ATTR_USERNAME: admin_user.username},
			format="json",
		)

		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("code") == "user_anti_lockout"
		m_ldap_user_exists.assert_not_called()
		m_ldap_user_delete.assert_not_called()


class TestChangePassword(BaseViewTestClass):
	_endpoint = "ldap/users-change-password"

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
		m_get_user_object.assert_called_once_with(
			username=m_data[LOCAL_ATTR_USERNAME]
		)
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
		assert response.data.get("code") == "user_does_not_exist"
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
		"headers": [
			LOCAL_ATTR_USERNAME,
			LOCAL_ATTR_EMAIL,
			LOCAL_ATTR_FIRST_NAME,
			LOCAL_ATTR_LAST_NAME,
		],
		"users": [
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
		"mapping": {
			h: h
			for h in (
				LOCAL_ATTR_USERNAME,
				LOCAL_ATTR_EMAIL,
				LOCAL_ATTR_FIRST_NAME,
				LOCAL_ATTR_LAST_NAME,
			)
		},
		"placeholder_password": "mock_password",
	}
	return result


class TestBulkCreate(BaseViewTestClass):
	_endpoint = "ldap/users-bulk-create"

	def test_success_csv(
		self,
		mocker: MockerFixture,
		admin_user: User,
		admin_user_client: APIClient,
		f_default_ldap_path: dict,
	):
		m_username_1 = "importeduser1"
		m_username_2 = "importeduser2"
		m_username_3 = "importeduser3"
		m_email_1 = "iu1@example.com"
		m_email_2 = "iu2@example.com"
		m_email_3 = "iu3@example.com"
		m_path = list(f_default_ldap_path.values())[0]
		m_users = [
			[
				m_username_1,
				m_email_1,
				"First",
				"Last",
			],
			[
				m_username_2,
				m_email_2,
				"First",
				"Last",
			],
			[
				m_username_3,
				m_email_3,
				"First",
				"Last",
			],
		]
		m_data = {
			"headers": "mock_headers",
			"mapping": "mock_mapping",
			"users": m_users,
			"path": m_path,
		}
		m_index_map = {0: LOCAL_ATTR_USERNAME, 1: LOCAL_ATTR_EMAIL}
		m_index_map_fn = mocker.patch.object(
			LDAPUserViewSet,
			"validate_and_map_csv_headers",
			return_value=m_index_map,
		)
		m_bulk_check_users = mocker.patch.object(
			LDAPUserViewSet,
			"bulk_check_users",
			return_value=[m_username_3],
		)
		m_bulk_create_from_csv = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_bulk_create_from_csv",
			return_value=([m_username_1, m_username_2], []),
		)
		m_bulk_create_from_dicts = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_bulk_create_from_dicts",
		)

		# Execution
		response: Response = admin_user_client.post(
			self.endpoint,
			data=m_data,
			format="json",
		)

		# Assertions
		assert response.status_code == status.HTTP_200_OK
		assert response.data.get("created_users") == [
			m_username_1,
			m_username_2,
		]
		assert response.data.get("failed_users") == []
		assert response.data.get("skipped_users") == [m_username_3]
		m_index_map_fn.assert_called_once_with(
			headers=m_data["headers"],
			csv_map=m_data["mapping"],
			check_attrs=DEFAULT_LOCAL_ATTRS,
		)
		m_bulk_check_users.assert_called_once_with(
			[
				(m_username_1, m_email_1),
				(m_username_2, m_email_2),
				(m_username_3, m_email_3),
			],
			ignore_local=True,
			raise_exception=False,
		)
		m_bulk_create_from_csv.assert_called_once_with(
			request_user=admin_user,
			user_rows=m_users,
			index_map=m_index_map,
			path=m_path,
			placeholder_password=None,
			skipped_users=[m_username_3],
		)
		m_bulk_create_from_dicts.assert_not_called()

	def test_success_dicts(
		self,
		mocker: MockerFixture,
		admin_user: User,
		admin_user_client: APIClient,
	):
		m_username = "importeduser1"
		m_email = "iu1@example.com"
		m_users = [
			{
				LOCAL_ATTR_USERNAME: m_username,
				LOCAL_ATTR_EMAIL: m_email,
			}
		]
		m_data = {"dict_users": m_users}
		m_index_map_fn = mocker.patch.object(
			LDAPUserViewSet,
			"validate_and_map_csv_headers",
		)
		m_bulk_check_users = mocker.patch.object(
			LDAPUserViewSet,
			"bulk_check_users",
			return_value=[],
		)
		m_bulk_create_from_csv = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_bulk_create_from_csv",
		)
		m_bulk_create_from_dicts = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_bulk_create_from_dicts",
			return_value=([m_username], []),
		)

		# Execution
		response: Response = admin_user_client.post(
			self.endpoint,
			data=m_data,
			format="json",
		)

		# Assertions
		assert response.status_code == status.HTTP_200_OK
		assert response.data.get("created_users") == [m_username]
		assert response.data.get("failed_users") == []
		assert response.data.get("skipped_users") == []
		m_index_map_fn.assert_not_called()
		m_bulk_create_from_csv.assert_not_called()
		m_bulk_check_users.assert_called_once_with(
			[(m_username, m_email)],
			ignore_local=True,
			raise_exception=False,
		)
		m_bulk_create_from_dicts.assert_called_once_with(
			request_user=admin_user,
			user_dicts=m_users,
			path=None,
			placeholder_password=None,
			skipped_users=[],
		)

	def test_raises_overlapping_operations(
		self,
		mocker: MockerFixture,
		admin_user: User,
		admin_user_client: APIClient,
	):
		m_index_map_fn = mocker.patch.object(
			LDAPUserViewSet,
			"validate_and_map_csv_headers",
		)
		m_bulk_check_users = mocker.patch.object(
			LDAPUserViewSet,
			"bulk_check_users",
		)
		m_bulk_create_from_csv = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_bulk_create_from_csv",
		)
		m_bulk_create_from_dicts = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_bulk_create_from_dicts",
		)
		m_data = {
			"users": "somevalue",
			"dict_users": "somevalue",
		}

		# Execution
		response: Response = admin_user_client.post(
			self.endpoint,
			data=m_data,
			format="json",
		)

		# Assertions
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		m_index_map_fn.assert_not_called()
		m_bulk_create_from_csv.assert_not_called()
		m_bulk_check_users.assert_not_called()
		m_bulk_create_from_dicts.assert_not_called()


@pytest.fixture
def f_bulk_update_data():
	return {
		"users": ["testuser1", "testuser2"],
		LOCAL_ATTR_PERMISSIONS: [LDAP_UF_NORMAL_ACCOUNT],
		"values": {
			LOCAL_ATTR_COUNTRY: "Argentina",
		},
	}


class TestBulkUpdate(BaseViewTestClass):
	_endpoint = "ldap/users-bulk-update"

	def test_success(
		self,
		admin_user_client: APIClient,
		f_bulk_update_data: dict,
		mocker: MockerFixture,
	):
		expected_user_count = len(f_bulk_update_data["users"])
		m_exists = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_exists", return_value=True
		)
		m_update = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_update", return_value=True
		)
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
			m_update.assert_any_call(
				data={
					LOCAL_ATTR_USERNAME: u,
					LOCAL_ATTR_PERMISSIONS: f_bulk_update_data[
						LOCAL_ATTR_PERMISSIONS
					],
					LOCAL_ATTR_COUNTRY: "Argentina",
				}
			)

	def test_not_exists_raises(
		self,
		admin_user_client: APIClient,
		f_bulk_update_data: dict,
		mocker: MockerFixture,
	):
		m_exists = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_exists", return_value=False
		)
		m_update = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_update", return_value=None
		)
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
			LDAPUserViewSet, "ldap_user_exists", return_value=True
		)
		m_update = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_update", return_value=None
		)
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
			LDAPUserViewSet, "ldap_user_exists", return_value=True
		)
		m_update = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_update", side_effect=Exception
		)
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
		"users": [
			{LOCAL_ATTR_USERNAME: "testuser1"},
			{LOCAL_ATTR_USERNAME: "testuser2"},
		],
		LOCAL_ATTR_ENABLED: False,
	}


class TestBulkChangeStatus(BaseViewTestClass):
	_endpoint = "ldap/users-bulk-change-status"

	@pytest.mark.parametrize(
		"flatten_users, enabled, expected",
		(
			(
				False,
				False,
				False,
			),
			(
				False,
				True,
				True,
			),
			(
				True,
				False,
				False,
			),
			(
				True,
				True,
				True,
			),
		),
		ids=[
			"User dict list, enable is True, expects enable False",
			"User dict list, enable is False, expects enable True",
			"Username list, enable is True, expects enable False",
			"Username list, enable is False, expects enable True",
		],
	)
	def test_success(
		self,
		flatten_users: bool,
		enabled: bool,
		expected: bool,
		admin_user_client: APIClient,
		f_logger: Logger,
		f_bulk_change_status_data: dict,
		mocker: MockerFixture,
	):
		if flatten_users:
			f_bulk_change_status_data["users"] = [
				u.get(LOCAL_ATTR_USERNAME)
				for u in f_bulk_change_status_data["users"]
			]
		f_bulk_change_status_data[LOCAL_ATTR_ENABLED] = enabled
		user_count = len(f_bulk_change_status_data["users"])
		m_change_status = mocker.patch.object(
			LDAPUserViewSet,
			"ldap_user_change_status",
			side_effect=(
				None,
				Exception,
			),
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
		del f_bulk_change_status_data[LOCAL_ATTR_ENABLED]
		m_change_status = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_change_status"
		)
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
			{"users": []},
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
			LDAPUserViewSet, "ldap_user_change_status"
		)
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
		{LOCAL_ATTR_USERNAME: "testuser1"},
		{LOCAL_ATTR_USERNAME: "testuser2"},
	]


class TestBulkDestroy(BaseViewTestClass):
	_endpoint = "ldap/users-bulk-destroy"

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
		mocker: MockerFixture,
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
			m_delete.assert_any_call(username=u.get(LOCAL_ATTR_USERNAME))


class TestBulkUnlock(BaseViewTestClass):
	_endpoint = "ldap/users-bulk-unlock"

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
		mocker: MockerFixture,
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
			m_unlock.assert_any_call(username=u.get(LOCAL_ATTR_USERNAME))

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


class TestSelfChangePassword(BaseViewTestClass):
	_endpoint = "ldap/users-self-change-password"

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
			(
				{
					LOCAL_ATTR_PASSWORD: False,
					LOCAL_ATTR_PASSWORD_CONFIRM: "mock_password",
				},
				"Not a valid string",
			),
			(
				{
					LOCAL_ATTR_PASSWORD: "mock_password",
					LOCAL_ATTR_PASSWORD_CONFIRM: None,
				},
				"may not be null",
			),
			(
				{
					LOCAL_ATTR_PASSWORD: "some_mock_password",
					LOCAL_ATTR_PASSWORD_CONFIRM: "mock_password_does_not_match",
				},
				"Passwords do not match",
			),
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
			"core.views.ldap.user.LDAPUser", return_value=m_ldap_user
		)
		# Mock set password method
		m_set_password = mocker.patch.object(
			LDAPUserViewSet, "ldap_set_password"
		)

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
			],
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
			"core.views.ldap.user.LDAPUser", return_value=m_ldap_user
		)
		# Mock set password method
		m_set_password = mocker.patch.object(
			LDAPUserViewSet, "ldap_set_password"
		)

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
			],
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
			"core.views.ldap.user.LDAPUser", return_value=m_ldap_user
		)
		# Mock set password method
		m_set_password = mocker.patch.object(
			LDAPUserViewSet, "ldap_set_password"
		)

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
			],
		)
		m_set_password.assert_called_once_with(
			user_dn=normal_user.distinguished_name,
			user_pwd_new="mock_password",
			set_by_admin=True,
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


class TestSelfUpdate(BaseViewTestClass):
	_endpoint = "ldap/users-self-update"

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
				LOCAL_ATTR_COUNTRY: "Some Country",
			},
			{LOCAL_ATTR_DN: "some_dn", LOCAL_ATTR_COUNTRY: "Some Country"},
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
			LOCAL_ATTR_PERMISSIONS: [
				LDAP_UF_NORMAL_ACCOUNT,
				LDAP_UF_ACCOUNT_DISABLE,
			],
		}
		m_ldap_user_update = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_update"
		)

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
		expected_data = m_data.copy() | {
			LOCAL_ATTR_USERNAME: normal_user.username
		}
		for key in (
			LOCAL_ATTR_IS_ENABLED,
			LOCAL_ATTR_UAC,
			LOCAL_ATTR_PERMISSIONS,
		):
			expected_data.pop(key, None)
		m_ldap_user_update.assert_called_once_with(data=expected_data)
		normal_user.refresh_from_db()
		normal_user.email == m_email


class TestSelfInfo(BaseViewTestClass):
	_endpoint = "ldap/users-self-info"

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
			LOCAL_ATTR_USERTYPE,
		)
		for attr in _ATTRS_TO_CHECK:
			assert data.get(attr) == getattr(_user, attr)
		assert data.get("admin_allowed", False) == expects_admin


class TestSelfFetch(BaseViewTestClass):
	_endpoint = "ldap/users-self-fetch"

	def test_success_ldap(
		self,
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
		normal_user.save()
		normal_user.refresh_from_db()
		mock_attrs = {
			LOCAL_ATTR_FIRST_NAME: normal_user.first_name,
			LOCAL_ATTR_LAST_NAME: normal_user.last_name,
			LOCAL_ATTR_FULL_NAME: "%s %s"
			% (normal_user.first_name, normal_user.last_name),
			LOCAL_ATTR_USERNAME: normal_user.username,
			LOCAL_ATTR_EMAIL: normal_user.email,
			LOCAL_ATTR_PHONE: "+5491112345678",
			LOCAL_ATTR_ADDRESS: "Some Address",
			LOCAL_ATTR_POSTAL_CODE: "PTLCOD",
			LOCAL_ATTR_CITY: "Mock City",
			LOCAL_ATTR_STATE: "Mock State",
			LOCAL_ATTR_COUNTRY: "Mock Country",
			LOCAL_ATTR_COUNTRY_DCC: "MC",
			LOCAL_ATTR_COUNTRY_ISO: 117,
			LOCAL_ATTR_WEBSITE: "test.example.com",
			LOCAL_ATTR_DN: normal_user.distinguished_name,
			LOCAL_ATTR_UPN: "%s@%s"
			% (
				normal_user.username,
				f_runtime_settings.LDAP_DOMAIN,
			),
			LOCAL_ATTR_CREATED: tz_aware_now(),
			LOCAL_ATTR_MODIFIED: tz_aware_now(),
			LOCAL_ATTR_LAST_LOGIN_WIN32: tz_aware_now(),
			LOCAL_ATTR_BAD_PWD_COUNT: 0,
		}

		m_ldap_user_fetch = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_fetch", return_value=mock_attrs
		)

		response: Response = normal_user_client.get(self.endpoint)

		assert response.status_code == status.HTTP_200_OK
		m_ldap_user_fetch.assert_called_once_with(
			user_search=normal_user.username
		)
		data = response.data.get("data")
		for attr in LOCAL_PUBLIC_FIELDS:
			if attr in data:
				assert data[attr] == mock_attrs[attr]

	def test_success_local(
		self,
		normal_user: User,
		normal_user_client: APIClient,
		mocker: MockerFixture,
	):
		m_ldap_user_fetch = mocker.patch.object(
			LDAPUserViewSet, "ldap_user_fetch"
		)

		response: Response = normal_user_client.get(self.endpoint)

		assert response.status_code == status.HTTP_200_OK
		m_ldap_user_fetch.assert_not_called()
		data = response.data.get("data")
		assert data[LOCAL_ATTR_USERNAME] == normal_user.username
		assert data[LOCAL_ATTR_USERTYPE] == USER_TYPE_LOCAL
		assert data[LOCAL_ATTR_FIRST_NAME] == normal_user.first_name
		assert data[LOCAL_ATTR_LAST_NAME] == normal_user.last_name
		assert data[LOCAL_ATTR_EMAIL] == normal_user.email
		assert data[LOCAL_ATTR_IS_ENABLED]
		assert not data[LOCAL_ATTR_DN]
		assert datetime.strptime(
			data[LOCAL_ATTR_LAST_LOGIN],
			DATE_FORMAT_ISO_8601_ALT,
		)
		assert datetime.strptime(
			data[LOCAL_ATTR_CREATED],
			DATE_FORMAT_ISO_8601_ALT,
		)
		assert datetime.strptime(
			data[LOCAL_ATTR_MODIFIED],
			DATE_FORMAT_ISO_8601_ALT,
		)
