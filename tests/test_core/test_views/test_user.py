########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType
################################################################################
from tests.test_core.test_views.conftest import (
	BaseViewTestClass,
	BaseViewTestClassWithPk,
)
from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework import status
from core.models.user import User
from core.exceptions.ldap import LDAPObjectExists
from tests.test_core.test_views.conftest import UserFactory, APIClientFactory
from tests.test_core.conftest import ConnectorFactory, LDAPConnectorMock
from core.constants.attrs.local import (
	LOCAL_ATTR_ID,
	LOCAL_ATTR_DN,
	LOCAL_ATTR_USERNAME,
	LOCAL_ATTR_USERTYPE,
	LOCAL_ATTR_PASSWORD,
	LOCAL_ATTR_PASSWORD_CONFIRM,
	LOCAL_ATTR_EMAIL,
	LOCAL_ATTR_IS_ENABLED,
	LOCAL_ATTR_ENABLED,
	LOCAL_ATTR_FIRST_NAME,
	LOCAL_ATTR_LAST_NAME,
)
from core.models.choices.log import (
	LOG_CLASS_USER,
	LOG_ACTION_CREATE,
	LOG_ACTION_UPDATE,
	LOG_ACTION_READ,
	LOG_ACTION_DELETE,
	LOG_EXTRA_ENABLE,
	LOG_EXTRA_DISABLE,
	LOG_EXTRA_USER_CHANGE_PASSWORD,
	LOG_EXTRA_USER_END_USER_UPDATE,
)
from core.constants.user import LOCAL_PUBLIC_FIELDS

@pytest.fixture(autouse=True)
def f_ldap_connector(g_ldap_connector: ConnectorFactory):
	return g_ldap_connector(patch_path="core.views.user.LDAPConnector")

@pytest.fixture
def f_user_test(user_factory: UserFactory) -> User:
	return user_factory(
		username="mock_user",
		email="mockuser@example.com",
	)

@pytest.fixture
def f_log(mocker: MockerFixture):
	return mocker.patch("core.views.user.DBLogMixin.log")

class TestList(BaseViewTestClass):
	_endpoint = "users-list"

	def test_success(
		self,
		admin_user_client: APIClient,
		f_user_test: User,
		f_user_ldap: User,
	):
		response: Response = admin_user_client.get(self.endpoint)
		response_users: list[dict] = response.data.get("users")
		assert response.status_code == status.HTTP_200_OK
		assert f_user_test.username in {
			u.get(LOCAL_ATTR_USERNAME) for u in response_users
		}
		assert f_user_ldap.distinguished_name in {
			u.get(LOCAL_ATTR_DN) for u in response_users
		}
		assert len(response.data.get("users")) == 3
		assert set(response.data.get("headers")) == set(
			[
				LOCAL_ATTR_USERNAME,
				LOCAL_ATTR_USERTYPE,
				LOCAL_ATTR_EMAIL,
				LOCAL_ATTR_IS_ENABLED,
			]
		)


class TestInsert(BaseViewTestClass):
	_endpoint = "users-insert"

	@pytest.mark.parametrize(
		"with_password",
		(
			True,
			False
		),
	)
	def test_success_with_ldap_disabled(
		self,
		with_password: bool,
		admin_user_client: APIClient,
		mocker: MockerFixture,
		g_interlock_ldap_disabled,
		f_log: MockType,
	):
		m_data = {
			LOCAL_ATTR_USERNAME: "new_user",
			LOCAL_ATTR_PASSWORD: "newpassword123",
			LOCAL_ATTR_PASSWORD_CONFIRM: "newpassword123",
			LOCAL_ATTR_EMAIL: "new@example.com",
			LOCAL_ATTR_IS_ENABLED: True,
		}
		if not with_password:
			m_password = m_data.pop(LOCAL_ATTR_PASSWORD)
			del m_data[LOCAL_ATTR_PASSWORD_CONFIRM]

		m_ldap_user_exists = mocker.patch(
			"core.views.user.UserViewSet.ldap_user_exists"
		)

		response: Response = admin_user_client.post(
			self.endpoint,
			data=m_data,
			format="json",
		)

		assert response.status_code == status.HTTP_200_OK
		assert response.data == {"code": 0, "code_msg": "ok"}

		# Verify user creation
		user: User = User.objects.get(username=m_data[LOCAL_ATTR_USERNAME])
		assert user.email == m_data[LOCAL_ATTR_EMAIL]
		m_ldap_user_exists.assert_not_called()
		if with_password:
			assert user.check_password(m_data[LOCAL_ATTR_PASSWORD])
		else:
			assert not user.check_password(m_password)
			assert not user.check_password("")

		# Verify logging
		f_log.assert_called_once_with(
			user=mocker.ANY,  # request.user.id
			operation_type=LOG_ACTION_CREATE,
			log_target_class=LOG_CLASS_USER,
			log_target=m_data[LOCAL_ATTR_USERNAME],
		)

	def test_success_with_ldap_enabled(
		self,
		mocker: MockerFixture,
		f_ldap_connector: LDAPConnectorMock,
		admin_user_client: APIClient,
		g_interlock_ldap_enabled,
		f_log: MockType,
	):
		user_data = {
			LOCAL_ATTR_USERNAME: "ldap_user",
			LOCAL_ATTR_PASSWORD: "mockpassword",
			LOCAL_ATTR_PASSWORD_CONFIRM: "mockpassword",
			LOCAL_ATTR_EMAIL: "ldap@example.com",
			LOCAL_ATTR_IS_ENABLED: True,
		}
		m_ldap_user_exists = mocker.patch(
			"core.views.user.UserViewSet.ldap_user_exists", return_value=False
		)

		response: Response = admin_user_client.post(self.endpoint, user_data)

		assert response.status_code == status.HTTP_200_OK
		assert response.data == {"code": 0, "code_msg": "ok"}

		# Verify LDAP checks
		f_ldap_connector.cls_mock.assert_called_once_with(force_admin=True)
		m_ldap_user_exists.assert_called_once_with(
			username=user_data[LOCAL_ATTR_USERNAME]
		)

		# Verify user creation
		user: User = User.objects.get(username=user_data[LOCAL_ATTR_USERNAME])
		assert user.email == user_data[LOCAL_ATTR_EMAIL]

		# Verify logging
		f_log.assert_called_once_with(
			user=mocker.ANY,
			operation_type=LOG_ACTION_CREATE,
			log_target_class=LOG_CLASS_USER,
			log_target=user_data[LOCAL_ATTR_USERNAME],
		)

	def test_serializer_validation_failure(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
	):
		"""Test invalid payload returns BadRequest"""
		invalid_data = {
			LOCAL_ATTR_USERNAME: "someuser",
			LOCAL_ATTR_EMAIL: "invalid-email",
			LOCAL_ATTR_PASSWORD_CONFIRM: "mockpassword",
			# Missing password
		}
		m_ldap_user_exists = mocker.patch(
			"core.views.user.UserViewSet.ldap_user_exists"
		)

		response: Response = admin_user_client.post(self.endpoint, invalid_data)

		assert response.status_code == status.HTTP_400_BAD_REQUEST
		m_ldap_user_exists.assert_not_called()
		assert "errors" in response.data
		assert LOCAL_ATTR_EMAIL in response.data["errors"]

	def test_serializer_password_validation_failure(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
	):
		"""Test invalid payload returns BadRequest"""
		invalid_data = {
			LOCAL_ATTR_USERNAME: "someuser",
			LOCAL_ATTR_EMAIL: "email@example.com",
			LOCAL_ATTR_PASSWORD: "mockpassword",
			# Missing password confirm
		}
		m_ldap_user_exists = mocker.patch(
			"core.views.user.UserViewSet.ldap_user_exists"
		)

		response: Response = admin_user_client.post(self.endpoint, invalid_data)

		assert response.status_code == status.HTTP_400_BAD_REQUEST
		m_ldap_user_exists.assert_not_called()
		assert "errors" in response.data
		assert LOCAL_ATTR_PASSWORD_CONFIRM in response.data["errors"]

	def test_ldap_user_exists_raises_error(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		f_ldap_connector: LDAPConnectorMock,
		g_interlock_ldap_enabled,
	):
		user_data = {
			LOCAL_ATTR_USERNAME: "existing_user",
			LOCAL_ATTR_PASSWORD: "mockpassword",
			LOCAL_ATTR_PASSWORD_CONFIRM: "mockpassword",
			LOCAL_ATTR_EMAIL: "exists@example.com",
		}
		m_ldap_user_exists = mocker.patch(
			"core.views.user.UserViewSet.ldap_user_exists",
			side_effect=LDAPObjectExists(data={
				"detail":"User already exists in LDAP"
			}),
		)

		response: Response = admin_user_client.post(self.endpoint, user_data)

		assert response.status_code == status.HTTP_409_CONFLICT
		m_ldap_user_exists.assert_called_once_with(
			username=user_data[LOCAL_ATTR_USERNAME]
		)
		assert "User already exists in LDAP" in response.data.get("detail")

		# Verify no user was created
		assert not User.objects.filter(
			username=user_data[LOCAL_ATTR_USERNAME]
		).exists()

class TestFetch(BaseViewTestClassWithPk):
	_endpoint = "users-fetch"

	def test_success(
		self,
		admin_user_client: APIClient,
		admin_user: User,
		f_user_test: User,
		f_log: MockType,
	):
		self._pk = f_user_test.id

		response: Response = admin_user_client.get(self.endpoint)
		response_data: dict = response.data.get("data")

		assert response.status_code == status.HTTP_200_OK
		for fld in LOCAL_PUBLIC_FIELDS:
			assert fld in response_data
			assert response_data[fld] == getattr(f_user_test, fld)
		f_log.assert_called_once_with(
			user=admin_user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_USER,
			log_target=f_user_test.username,
		)

	def test_raises_user_not_exist(
		self,
		admin_user_client: APIClient,
		f_log: MockType,
	):
		self._pk = 999

		response: Response = admin_user_client.get(self.endpoint)

		assert response.status_code == status.HTTP_404_NOT_FOUND
		f_log.assert_not_called()


class TestUpdate(BaseViewTestClass):
	_endpoint = "users-list"

	def test_success(
		self,
		admin_user_client: APIClient,
		admin_user: User,
		f_user_test: User,
		f_log: MockType,
	):
		m_password = "newpassword123"

		response: Response = admin_user_client.put(
			self.endpoint + f"{f_user_test.id}/",
			data={
				LOCAL_ATTR_DN: "some_dn",
				LOCAL_ATTR_EMAIL: "new.email@example.com",
				LOCAL_ATTR_PASSWORD: m_password,
				LOCAL_ATTR_PASSWORD_CONFIRM: m_password,
			},
			format="json",
		)

		assert response.status_code == status.HTTP_200_OK

		f_user_test.refresh_from_db()
		assert f_user_test.email == "new.email@example.com"
		assert f_user_test.check_password(m_password)
		f_log.assert_called_once_with(
			user=admin_user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=f_user_test.username,
		)

	def test_raises_user_not_exists(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		f_user_test: User,
		f_log: MockType,
	):
		m_save = mocker.patch.object(User, "save")
		response: Response = admin_user_client.put(
			self.endpoint + f"999/",
			data={LOCAL_ATTR_EMAIL: "new.email@example.com"},
			format="json",
		)

		assert response.status_code == status.HTTP_404_NOT_FOUND

		f_user_test.refresh_from_db()
		assert f_user_test.email != "new.email@example.com"
		m_save.assert_not_called()
		f_log.assert_not_called()

	def test_raises_user_not_local(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		f_user_ldap: User,
		f_log: MockType,
	):
		m_save = mocker.patch.object(User, "save")
		response: Response = admin_user_client.put(
			self.endpoint + f"{f_user_ldap.id}/",
			data={LOCAL_ATTR_EMAIL: "new.email@example.com"},
			format="json",
		)

		assert response.status_code == status.HTTP_406_NOT_ACCEPTABLE

		f_user_ldap.refresh_from_db()
		assert f_user_ldap.email != "new.email@example.com"
		m_save.assert_not_called()
		f_log.assert_not_called()

	def test_raises_serializer_error(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		f_user_test: User,
		f_log: MockType,
	):
		m_save = mocker.patch.object(User, "save")
		m_password = "newpassword123"

		response: Response = admin_user_client.put(
			self.endpoint + f"{f_user_test.id}/",
			data={
				LOCAL_ATTR_EMAIL: "bad-email",
				LOCAL_ATTR_PASSWORD: m_password,
			},
		)
		response_errors = response.data.get("errors")

		assert response.status_code == status.HTTP_400_BAD_REQUEST

		f_user_test.refresh_from_db()
		m_save.assert_not_called()
		f_log.assert_not_called()
		assert LOCAL_ATTR_EMAIL in response_errors
		# Password confirm validation is done after Model fields.
		assert LOCAL_ATTR_PASSWORD not in response_errors
		assert not f_user_test.check_password(m_password)


class TestDelete(BaseViewTestClassWithPk):
	_endpoint = "users-delete"

	def test_success(
		self,
		admin_user_client: APIClient,
		admin_user: User,
		f_user_test: User,
		f_log: MockType,
	):
		self._pk = f_user_test.id

		response: Response = admin_user_client.delete(self.endpoint)
		assert response.status_code == status.HTTP_200_OK
		assert not User.objects.filter(username=f_user_test.username).exists()
		f_log.assert_called_once_with(
			user=admin_user.id,
			operation_type=LOG_ACTION_DELETE,
			log_target_class=LOG_CLASS_USER,
			log_target=f_user_test.username,
		)

	def test_raises_not_exists(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		f_log: MockType,
	):
		m_delete_permanently = mocker.patch.object(User, "delete_permanently")
		self._pk = 999

		response: Response = admin_user_client.delete(self.endpoint)
		assert response.status_code == status.HTTP_404_NOT_FOUND
		m_delete_permanently.assert_not_called()
		f_log.assert_not_called()

	def test_raises_anti_lockout(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		admin_user: User,
		f_log: MockType,
	):
		m_delete_permanently = mocker.patch.object(User, "delete_permanently")
		self._pk = admin_user.id

		response: Response = admin_user_client.delete(self.endpoint)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert User.objects.filter(username=admin_user.username).exists()
		m_delete_permanently.assert_not_called()
		f_log.assert_not_called()

	def test_raises_not_local(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		f_user_ldap: User,
		f_log: MockType,
	):
		m_delete_permanently = mocker.patch.object(User, "delete_permanently")
		self._pk = f_user_ldap.id

		response: Response = admin_user_client.delete(self.endpoint)
		assert response.status_code == status.HTTP_406_NOT_ACCEPTABLE
		assert User.objects.filter(username=f_user_ldap.username).exists()
		m_delete_permanently.assert_not_called()
		f_log.assert_not_called()


class TestChangeStatus(BaseViewTestClassWithPk):
	_endpoint = "users-change-status"

	@pytest.mark.parametrize(
		"enabled, mock_opposite",
		(
			(True, True),
			(False, True),
			(True, False),
			(False, False),
		),
	)
	def test_success(
		self,
		enabled: bool,
		mock_opposite: bool,
		admin_user_client: APIClient,
		admin_user: User,
		f_user_test: User,
		f_log: MockType,
	):
		self._pk = f_user_test.id

		# Mock opposite value
		if mock_opposite:
			f_user_test.is_enabled = (not enabled)
			f_user_test.save()

		response: Response = admin_user_client.post(
			self.endpoint,
			data={LOCAL_ATTR_ENABLED: enabled},
			format="json",
		)
		assert response.status_code == status.HTTP_200_OK
		f_user_test.refresh_from_db()
		assert f_user_test.is_enabled == enabled
		f_log.assert_called_once_with(
			user=admin_user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=f_user_test.username,
			message=LOG_EXTRA_ENABLE if enabled else LOG_EXTRA_DISABLE,
		)

	def test_raises_not_local(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		f_user_ldap: User,
		f_log: MockType,	
	):
		m_save = mocker.patch.object(User, "save")
		self._pk = f_user_ldap.id
		response: Response = admin_user_client.post(
			self.endpoint,
			data={LOCAL_ATTR_ENABLED: True},
			format="json",
		)
		assert response.status_code == status.HTTP_406_NOT_ACCEPTABLE
		m_save.assert_not_called()
		f_log.assert_not_called()

	def test_raises_antilockout(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		admin_user: User,
		f_log: MockType,	
	):
		m_save = mocker.patch.object(User, "save")
		self._pk = admin_user.id
		response: Response = admin_user_client.post(
			self.endpoint,
			data={LOCAL_ATTR_ENABLED: True},
			format="json",
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		m_save.assert_not_called()
		f_log.assert_not_called()

	def test_raises_not_exists(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		f_log: MockType,	
	):
		m_save = mocker.patch.object(User, "save")
		self._pk = 999
		response: Response = admin_user_client.post(
			self.endpoint,
			data={LOCAL_ATTR_ENABLED: True},
			format="json",
		)
		assert response.status_code == status.HTTP_404_NOT_FOUND
		m_save.assert_not_called()
		f_log.assert_not_called()

class TestChangePassword(BaseViewTestClassWithPk):
	_endpoint = "users-change-password"

	def test_success(
		self,
		admin_user_client: APIClient,
		admin_user: User,
		f_user_test: User,
		f_log: MockType,
	):
		self._pk = f_user_test.id
		m_password = "newpassword123"
		assert not f_user_test.check_password(m_password)

		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				LOCAL_ATTR_PASSWORD: m_password,
				LOCAL_ATTR_PASSWORD_CONFIRM: m_password,
			}
		)
		
		assert response.status_code == status.HTTP_200_OK
		assert response.data.get("data")\
			.get(LOCAL_ATTR_USERNAME) == f_user_test.username
		f_user_test.refresh_from_db()
		assert f_user_test.check_password(m_password)
		f_log.assert_called_once_with(
			user=admin_user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=f_user_test.username,
			message=LOG_EXTRA_USER_CHANGE_PASSWORD,
		)

	def test_raises_not_local(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		f_user_ldap: User,
		f_log: MockType,	
	):
		m_save = mocker.patch.object(User, "save")
		self._pk = f_user_ldap.id
		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				LOCAL_ATTR_PASSWORD: "mock",
				LOCAL_ATTR_PASSWORD_CONFIRM: "mock",
			},
			format="json",
		)
		assert response.status_code == status.HTTP_406_NOT_ACCEPTABLE
		m_save.assert_not_called()
		f_log.assert_not_called()

	def test_raises_not_exists(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		f_log: MockType,	
	):
		m_save = mocker.patch.object(User, "save")
		self._pk = 999
		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				LOCAL_ATTR_PASSWORD: "mock",
				LOCAL_ATTR_PASSWORD_CONFIRM: "mock",
			},
			format="json",
		)
		assert response.status_code == status.HTTP_404_NOT_FOUND
		m_save.assert_not_called()
		f_log.assert_not_called()

class TestSelfChangePassword(BaseViewTestClass):
	_endpoint = "users-self-change-password"

	def test_raises_not_local(
		self,
		mocker: MockerFixture,
		f_api_client: APIClientFactory,
		f_user_ldap: User,
		f_log: MockType,
	):
		ldap_user_client = f_api_client(user=f_user_ldap)
		m_save = mocker.patch.object(User, "save")
		response: Response = ldap_user_client.post(
			self.endpoint,
			data={},
			format="json",
		)
		assert response.status_code == status.HTTP_406_NOT_ACCEPTABLE
		m_save.assert_not_called()
		f_log.assert_not_called()

	@pytest.mark.parametrize(
		"invalid_key",
		(
			LOCAL_ATTR_USERNAME,
			LOCAL_ATTR_ID,
		),
	)
	def test_raises_on_invalid_keys(
		self,
		mocker: MockerFixture,
		invalid_key: str,
		f_api_client: APIClientFactory,
		f_user_local: User,
		f_log: MockType,
	):
		ldap_user_client = f_api_client(user=f_user_local)
		m_save = mocker.patch.object(User, "save")
		response: Response = ldap_user_client.post(
			self.endpoint,
			data={invalid_key: "some_value"},
			format="json",
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		m_save.assert_not_called()
		f_log.assert_not_called()

	def test_success(
		self,
		f_api_client: APIClientFactory,
		f_user_local: User,
		f_log: MockType,
	):
		ldap_user_client = f_api_client(user=f_user_local)
		m_password = "newpassword123"
		assert not f_user_local.check_password(m_password)

		response: Response = ldap_user_client.post(
			self.endpoint,
			data={
				LOCAL_ATTR_PASSWORD: m_password,
				LOCAL_ATTR_PASSWORD_CONFIRM: m_password,
			},
			format="json",
		)

		assert response.status_code == status.HTTP_200_OK
		assert response.data.get("data")\
			.get(LOCAL_ATTR_USERNAME) == f_user_local.username
		f_user_local.refresh_from_db()
		assert f_user_local.check_password(m_password)
		f_log.assert_called_once_with(
			user=f_user_local.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=f_user_local.username,
			message=LOG_EXTRA_USER_CHANGE_PASSWORD,
		)

class TestSelfUpdate(BaseViewTestClass):
	_endpoint = "users-self-update"

	def test_raises_not_local(
		self,
		mocker: MockerFixture,
		f_api_client: APIClientFactory,
		f_user_ldap: User,
		f_log: MockType,
	):
		ldap_user_client = f_api_client(user=f_user_ldap)
		m_save = mocker.patch.object(User, "save")
		response: Response = ldap_user_client.post(
			self.endpoint,
			data={},
			format="json",
		)
		assert response.status_code == status.HTTP_406_NOT_ACCEPTABLE
		m_save.assert_not_called()
		f_log.assert_not_called()

	def test_success(
		self,
		f_api_client: APIClientFactory,
		f_user_local: User,
		f_log: MockType,
	):
		m_data = {
			LOCAL_ATTR_FIRST_NAME: "New First Name",
			LOCAL_ATTR_LAST_NAME: "New Last Name",
			LOCAL_ATTR_EMAIL: "newemail@example.com",
		}
		m_api_client = f_api_client(user=f_user_local)
		response: Response = m_api_client.put(
			self.endpoint,
			data=m_data,
			format="json",
		)

		assert response.status_code == status.HTTP_200_OK
		f_user_local.refresh_from_db()
		assert f_user_local.first_name == m_data[LOCAL_ATTR_FIRST_NAME]
		assert f_user_local.last_name == m_data[LOCAL_ATTR_LAST_NAME]
		assert f_user_local.email == m_data[LOCAL_ATTR_EMAIL]
		f_log.assert_called_once_with(
			user=f_user_local.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=f_user_local.username,
			message=LOG_EXTRA_USER_END_USER_UPDATE,
		)

