########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture, MockType

################################################################################
from rest_framework.response import Response
from rest_framework import status
from core.views.ldap.user import LDAPUserViewSet
from rest_framework.test import APIClient
from core.exceptions.ldap import CouldNotOpenConnection
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from core.ldap.adsi import (
	LDAP_UF_DONT_EXPIRE_PASSWD,
	LDAP_UF_ACCOUNT_DISABLE,
	LDAP_UF_NORMAL_ACCOUNT,
)
from core.models.user import User, USER_TYPE_LDAP
from core.exceptions import (
	ldap as exc_ldap,
	users as exc_users,
)
from core.constants.attrs import (
	LOCAL_ATTR_USERNAME,
	LDAP_ATTR_DN,
	LDAP_ATTR_FULL_NAME,
	LDAP_ATTR_FIRST_NAME,
	LDAP_ATTR_LAST_NAME,
	LDAP_ATTR_INITIALS,
	LDAP_ATTR_USERNAME_SAMBA_ADDS,
	LDAP_ATTR_EMAIL,
)
from core.views.mixins.logs import LogMixin
from core.models.choices.log import (
	LOG_ACTION_UPDATE,
	LOG_CLASS_USER,
	LOG_EXTRA_USER_CHANGE_PASSWORD,
)
from tests.test_core.type_hints import LDAPConnectorMock


@pytest.fixture(autouse=True)
def f_log_mixin(mocker: MockerFixture):
	m_log_mixin = mocker.Mock(name="m_log_mixin")
	mocker.patch("core.views.ldap.user.DBLogMixin", m_log_mixin)
	return m_log_mixin


@pytest.fixture(autouse=True)
def f_ldap_connector(g_ldap_connector) -> LDAPConnectorMock:
	"""Fixture to mock LDAPConnector and its context manager."""
	return g_ldap_connector(patch_path="core.views.ldap.user.LDAPConnector")


@pytest.fixture(autouse=True)
def f_interlock_ldap_enabled(g_interlock_ldap_enabled):
	return g_interlock_ldap_enabled


@pytest.fixture
def f_runtime_settings(
	mocker: MockerFixture, g_runtime_settings: RuntimeSettingsSingleton
):
	mocker.patch("core.views.ldap.user.RuntimeSettings", g_runtime_settings)
	return g_runtime_settings


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
			"users": [{"username": "testuser", "is_enabled": True}],
			"headers": ["username", "is_enabled"],
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
		assert "username" in response.data["headers"]

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
			self.endpoint, data={"username": "testuser"}
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
					LDAP_ATTR_USERNAME_SAMBA_ADDS: "testuser",
					"path": "OU=mock ou,DC=example,DC=com",
					LDAP_ATTR_FIRST_NAME: "Test",
					LDAP_ATTR_LAST_NAME: "User",
					"password": "TestPassword",
					"passwordConfirm": "TestPassword",
					"permission_list": [
						LDAP_UF_DONT_EXPIRE_PASSWD,
						LDAP_UF_NORMAL_ACCOUNT,
					],
				},
				True,
			),
			(
				{
					LOCAL_ATTR_USERNAME: "testuser",
					"path": "OU=mock ou,DC=example,DC=com",
					LDAP_ATTR_FIRST_NAME: "Test",
					LDAP_ATTR_LAST_NAME: "User",
					"password": "TestPassword",
					"passwordConfirm": "TestPassword",
					"permission_list": [
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
			m_data[LDAP_ATTR_EMAIL] = (
				f"testuser@{f_runtime_settings.LDAP_DOMAIN}"
			)
		expected_m_data_call = m_data.copy()
		if LDAP_ATTR_USERNAME_SAMBA_ADDS in m_data:
			expected_m_data_call[LOCAL_ATTR_USERNAME] = expected_m_data_call[
				LDAP_ATTR_USERNAME_SAMBA_ADDS
			]
			expected_m_data_call.pop(LDAP_ATTR_USERNAME_SAMBA_ADDS, None)
		expected_m_data_call.pop("passwordConfirm", None)

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
			else m_data.get(f_runtime_settings.LDAP_AUTH_USER_FIELDS["email"]),
		)
		m_ldap_user_insert.assert_called_once_with(
			user_data=expected_m_data_call
		)
		m_ldap_set_password.assert_called_once_with(
			user_dn=m_distinguished_name,
			user_pwd_new=m_data.get("password"),
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
			m_data[LDAP_ATTR_EMAIL] = (
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
			else m_data.get(f_runtime_settings.LDAP_AUTH_USER_FIELDS["email"]),
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
			"password": "1234",
			"passwordConfirm": "4321",
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
		assert response.data.get("code") == "user_passwords_dont_match"
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
			"path": "OU=mock ou,DC=example,DC=com",
			LDAP_ATTR_EMAIL: f"testuser@{f_runtime_settings.LDAP_DOMAIN}",
			LDAP_ATTR_FIRST_NAME: "Test",
			LDAP_ATTR_LAST_NAME: "User",
			"permission_list": m_perm_list,
		}
		expected_m_data = m_data.copy()
		expected_m_data.pop("path", None)
		expected_m_data.pop("permission_list", None)
		expected_m_data.pop(LOCAL_ATTR_USERNAME, None)

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
			email=m_data.get(LDAP_ATTR_EMAIL),
		)
		m_ldap_user_update.assert_called_once_with(
			username=m_data.get(LOCAL_ATTR_USERNAME),
			user_data=expected_m_data,
			permission_list=m_perm_list,
		)

	def test_raises_anti_lockout(
		self,
		admin_user: User,
		admin_user_client: APIClient,
		mocker: MockerFixture,
	):
		m_data = {
			LOCAL_ATTR_USERNAME: admin_user.username,
			"permission_list": [
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
			("path", "some_bad_dn"),
			("permission_list", "some_bad_perm"),
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
		expected_m_data.pop("path", None)
		expected_m_data.pop("permission_list", None)

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
			"path": "OU=mock ou,DC=example,DC=com",
		}
		expected_m_data = m_data.copy()
		expected_m_data.pop("path", None)
		expected_m_data.pop("permission_list", None)

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
		m_data = {"username": "someotheruser", "enabled": enabled}

		# Exec
		response: Response = admin_user_client.post(
			self.endpoint,
			data=m_data,
			format="json",
		)
		assert response.status_code == status.HTTP_200_OK
		m_change_status.assert_called_once_with(
			username=m_data["username"],
			enabled=enabled,
		)
		m_ldap_user_exists.assert_called_once_with(
			username=m_data["username"],
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
		m_data = {"username": "testuser", "enabled": True}
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
		m_data = {"username": admin_user.username, "enabled": True}

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
			data={"username": m_username},
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
				"password": "1234",
				"passwordConfirm": "4321",
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
			"username": m_user.username,
			"password": m_password,
			"passwordConfirm": m_password,
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
			username=m_data["username"],
			return_exception=False,
		)
		m_get_user_object.assert_called_once_with(username=m_data["username"])
		m_ldap_set_password.assert_called_once_with(
			user_dn=m_user_entry.entry_dn,
			user_pwd_new=m_data["password"],
			set_by_admin=True,
		)
		f_log_mixin.log.assert_called_once_with(
			user=admin_user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=m_data["username"],
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
			data={"username": "someuser"},
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
			data={"username": "someuser"},
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
			data={"username": "someuser"},
			format="json",
		)

		# Assertions
		assert response.status_code == status.HTTP_200_OK
		m_ldap_user_exists.assert_called_once_with(
			username="someuser",
			return_exception=False,
		)
		m_ldap_user_unlock.assert_called_once_with(username="someuser")


class TestBulkInsert:
	endpoint = "/api/ldap/users/bulk_insert/"


class TestBulkUpdate:
	endpoint = "/api/ldap/users/bulk_update/"


class TestBulkChangeStatus:
	endpoint = "/api/ldap/users/bulk_change_status/"


class TestBulkDelete:
	endpoint = "/api/ldap/users/bulk_delete/"


class TestBulkUnlock:
	endpoint = "/api/ldap/users/bulk_unlock/"


class TestSelfChangePassword:
	endpoint = "/api/ldap/users/self_change_password/"


class TestSelfUpdate:
	endpoint = "/api/ldap/users/self_update/"


class TestSelfInfo:
	endpoint = "/api/ldap/users/self_info/"


class TestSelfFetch:
	endpoint = "/api/ldap/users/self_fetch/"
