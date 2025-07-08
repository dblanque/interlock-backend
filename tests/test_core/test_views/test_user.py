########################### Standard Pytest Imports ############################
import pytest
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
from core.exceptions import users as exc_user
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
from core.views.user import UserViewSet


@pytest.fixture(autouse=True)
def f_ldap_connector(g_ldap_connector: ConnectorFactory):
	return g_ldap_connector(
		patch_path="core.views.mixins.user.main.LDAPConnector"
	)


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
		assert len(response.data.get("users")) == User.objects.all().count()
		assert set(response.data.get("headers")) == set(
			[
				LOCAL_ATTR_USERNAME,
				LOCAL_ATTR_USERTYPE,
				LOCAL_ATTR_EMAIL,
				LOCAL_ATTR_IS_ENABLED,
			]
		)


class TestCreate(BaseViewTestClass):
	_endpoint = "users-list"

	@pytest.mark.parametrize(
		"with_password",
		(True, False),
	)
	def test_success(
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

		m_check_user_exists = mocker.patch.object(
			UserViewSet,
			"check_user_exists",
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
		m_check_user_exists.assert_called_once_with(
			username=m_data[LOCAL_ATTR_USERNAME],
			email=m_data.get(LOCAL_ATTR_EMAIL, None),
			ignore_local=True,
		)
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
		m_check_user_exists = mocker.patch.object(
			UserViewSet,
			"check_user_exists",
		)

		response: Response = admin_user_client.post(self.endpoint, invalid_data)

		assert response.status_code == status.HTTP_400_BAD_REQUEST
		m_check_user_exists.assert_not_called()
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
		m_check_user_exists = mocker.patch.object(
			UserViewSet,
			"check_user_exists",
		)

		response: Response = admin_user_client.post(self.endpoint, invalid_data)

		assert response.status_code == status.HTTP_400_BAD_REQUEST
		m_check_user_exists.assert_not_called()
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
		m_check_user_exists = mocker.patch.object(
			UserViewSet, "check_user_exists", side_effect=exc_user.UserExists
		)
		response: Response = admin_user_client.post(self.endpoint, user_data)

		assert response.status_code == status.HTTP_409_CONFLICT
		m_check_user_exists.assert_called_once_with(
			username=user_data[LOCAL_ATTR_USERNAME],
			email=user_data[LOCAL_ATTR_EMAIL],
			ignore_local=True,
		)
		assert "already exists" in response.data.get("detail")

		# Verify no user was created
		assert not User.objects.filter(
			username=user_data[LOCAL_ATTR_USERNAME]
		).exists()


class TestRetrieve(BaseViewTestClassWithPk):
	_endpoint = "users-detail"

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
		mocker: MockerFixture,
		admin_user_client: APIClient,
		admin_user: User,
		f_user_test: User,
		f_log: MockType,
	):
		m_password = "newpassword123"
		m_check_user_exists = mocker.patch.object(
			UserViewSet,
			"check_user_exists",
		)

		m_data = {
			LOCAL_ATTR_DN: "some_dn",
			LOCAL_ATTR_EMAIL: "new.email@example.com",
			LOCAL_ATTR_PASSWORD: m_password,
			LOCAL_ATTR_PASSWORD_CONFIRM: m_password,
		}
		response: Response = admin_user_client.put(
			self.endpoint + f"{f_user_test.id}/",
			data=m_data,
			format="json",
		)

		assert response.status_code == status.HTTP_200_OK

		f_user_test.refresh_from_db()
		assert f_user_test.email == "new.email@example.com"
		assert f_user_test.check_password(m_password)
		m_check_user_exists.assert_called_once_with(
			username=m_data.get(LOCAL_ATTR_USERNAME, None),
			email=m_data.get(LOCAL_ATTR_EMAIL, None),
			ignore_local=True,
		)
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
		m_check_user_exists = mocker.patch.object(
			UserViewSet,
			"check_user_exists",
		)
		response: Response = admin_user_client.put(
			self.endpoint + "999/",
			data={LOCAL_ATTR_EMAIL: "new.email@example.com"},
			format="json",
		)

		assert response.status_code == status.HTTP_404_NOT_FOUND

		f_user_test.refresh_from_db()
		assert f_user_test.email != "new.email@example.com"
		m_check_user_exists.assert_not_called()
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
		m_check_user_exists = mocker.patch.object(
			UserViewSet,
			"check_user_exists",
		)
		response: Response = admin_user_client.put(
			self.endpoint + f"{f_user_ldap.id}/",
			data={LOCAL_ATTR_EMAIL: "new.email@example.com"},
			format="json",
		)

		assert response.status_code == status.HTTP_406_NOT_ACCEPTABLE

		f_user_ldap.refresh_from_db()
		assert f_user_ldap.email != "new.email@example.com"
		m_check_user_exists.assert_not_called()
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
		m_check_user_exists = mocker.patch.object(
			UserViewSet,
			"check_user_exists",
		)
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
		m_check_user_exists.assert_not_called()
		m_save.assert_not_called()
		f_log.assert_not_called()
		assert LOCAL_ATTR_EMAIL in response_errors
		# Password confirm validation is done after Model fields.
		assert LOCAL_ATTR_PASSWORD not in response_errors
		assert not f_user_test.check_password(m_password)


class TestDestroy(BaseViewTestClassWithPk):
	_endpoint = "users-detail"

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

	def test_accepts_not_local(
		self,
		mocker: MockerFixture,
		admin_user: User,
		admin_user_client: APIClient,
		f_user_ldap: User,
		f_log: MockType,
	):
		m_delete_permanently = mocker.patch.object(User, "delete_permanently")
		self._pk = f_user_ldap.id

		response: Response = admin_user_client.delete(self.endpoint)
		assert response.status_code == status.HTTP_200_OK
		assert User.objects.filter(username=f_user_ldap.username).exists()
		m_delete_permanently.assert_called_once()
		f_log.assert_called_once_with(
			user=admin_user.id,
			operation_type=LOG_ACTION_DELETE,
			log_target_class=LOG_CLASS_USER,
			log_target=f_user_ldap.username,
		)


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
			f_user_test.is_enabled = not enabled
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
			},
		)

		assert response.status_code == status.HTTP_200_OK
		assert (
			response.data.get("data").get(LOCAL_ATTR_USERNAME)
			== f_user_test.username
		)
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
		g_interlock_ldap_enabled,
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
		assert (
			response.data.get("data").get(LOCAL_ATTR_USERNAME)
			== f_user_local.username
		)
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
		g_interlock_ldap_enabled,
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


class TestBulkCreate(BaseViewTestClass):
	_endpoint = "users-bulk-create"

	def test_success_csv(
		self,
		mocker: MockerFixture,
		admin_user: User,
		admin_user_client: APIClient,
	):
		m_username_1 = "importeduser1"
		m_username_2 = "importeduser2"
		m_email_1 = "iu1@example.com"
		m_email_2 = "iu2@example.com"
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
		]
		m_data = {
			"headers": "mock_headers",
			"mapping": "mock_mapping",
			"users": m_users,
		}
		m_index_map = {0: LOCAL_ATTR_USERNAME, 1: LOCAL_ATTR_EMAIL}
		m_index_map_fn = mocker.patch.object(
			UserViewSet,
			"validate_and_map_csv_headers",
			return_value=m_index_map,
		)
		m_bulk_check_users = mocker.patch.object(
			UserViewSet,
			"bulk_check_users",
			return_value=[],
		)
		m_bulk_create_from_csv = mocker.patch.object(
			UserViewSet,
			"bulk_create_from_csv",
			return_value=([m_username_1, m_username_2], []),
		)
		m_bulk_create_from_dicts = mocker.patch.object(
			UserViewSet,
			"bulk_create_from_dicts",
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
		assert response.data.get("skipped_users") == []
		m_index_map_fn.assert_called_once_with(
			headers=m_data["headers"],
			csv_map=m_data["mapping"],
		)
		m_bulk_check_users.assert_called_once_with(
			[
				(m_username_1, m_email_1),
				(m_username_2, m_email_2),
			],
			raise_exception=False,
		)
		m_bulk_create_from_csv.assert_called_once_with(
			request_user=admin_user,
			user_rows=m_users,
			index_map=m_index_map,
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
			UserViewSet,
			"validate_and_map_csv_headers",
		)
		m_bulk_check_users = mocker.patch.object(
			UserViewSet,
			"bulk_check_users",
			return_value=[],
		)
		m_bulk_create_from_csv = mocker.patch.object(
			UserViewSet,
			"bulk_create_from_csv",
		)
		m_bulk_create_from_dicts = mocker.patch.object(
			UserViewSet,
			"bulk_create_from_dicts",
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
			raise_exception=False,
		)
		m_bulk_create_from_dicts.assert_called_once_with(
			request_user=admin_user, user_dicts=m_users
		)

	def test_raises_overlapping_operations(
		self,
		mocker: MockerFixture,
		admin_user: User,
		admin_user_client: APIClient,
	):
		m_index_map_fn = mocker.patch.object(
			UserViewSet,
			"validate_and_map_csv_headers",
		)
		m_bulk_check_users = mocker.patch.object(
			UserViewSet,
			"bulk_check_users",
		)
		m_bulk_create_from_csv = mocker.patch.object(
			UserViewSet,
			"bulk_create_from_csv",
		)
		m_bulk_create_from_dicts = mocker.patch.object(
			UserViewSet,
			"bulk_create_from_dicts",
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


class TestBulkUpdate(BaseViewTestClass):
	_endpoint = "users-bulk-update"

	@pytest.mark.parametrize(
		"delete_key",
		(
			"users",
			"values",
		),
	)
	def test_raises_on_missing_key(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		delete_key: str,
	):
		m_validated_user_pk_list = mocker.patch.object(
			UserViewSet,
			"validated_user_pk_list",
		)
		m_data = {
			"users": ["somelst"],
			"values": ["somelst"],
		}
		del m_data[delete_key]

		response: Response = admin_user_client.put(
			self.endpoint, data=m_data, format="json"
		)

		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("code") == "bad_request"
		m_validated_user_pk_list.assert_not_called()

	def test_raises_on_non_existing_user(
		self,
		admin_user_client: APIClient,
	):
		m_data = {
			"users": [999],
			"values": ["somelst"],
		}

		response: Response = admin_user_client.put(
			self.endpoint, data=m_data, format="json"
		)

		assert response.status_code == status.HTTP_404_NOT_FOUND
		assert response.data.get("code") == "user_does_not_exist"

	def test_success(
		self,
		admin_user: User,
		admin_user_client: APIClient,
		f_user_local: User,
		f_user_test: User,
		f_log: MockType,
	):
		m_users = (
			admin_user,
			f_user_local,
			f_user_test,
		)
		m_user_pks = [u.id for u in m_users]
		response: Response = admin_user_client.put(
			self.endpoint,
			data={
				"users": m_user_pks,
				"values": {
					LOCAL_ATTR_FIRST_NAME: "Mock",
					LOCAL_ATTR_LAST_NAME: "Name",
				},
			},
			format="json",
		)

		assert response.status_code == status.HTTP_200_OK
		assert response.data.get("updated_users") == len(m_user_pks)
		for u in m_users:
			u.refresh_from_db()
			assert getattr(u, LOCAL_ATTR_FIRST_NAME) == "Mock"
			assert getattr(u, LOCAL_ATTR_LAST_NAME) == "Name"
			f_log.assert_any_call(
				user=admin_user.id,
				operation_type=LOG_ACTION_UPDATE,
				log_target_class=LOG_CLASS_USER,
				log_target=u.username,
			)
		f_log.call_count == len(m_user_pks)


class TestBulkDestroy(BaseViewTestClass):
	_endpoint = "users-bulk-destroy"

	def test_raises_anti_lockout(
		self,
		mocker: MockerFixture,
		admin_user: User,
		admin_user_client: APIClient,
		f_user_local: User,
		f_user_ldap: User,
		f_log: MockType,
	):
		m_delete_permanently = mocker.patch.object(User, "delete_permanently")
		response: Response = admin_user_client.delete(
			self.endpoint,
			data={"users": [admin_user.id, f_user_ldap.id, f_user_local.id]},
			format="json",
		)

		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("code") == "user_anti_lockout"
		m_delete_permanently.assert_not_called()
		f_log.assert_not_called()

	def test_non_existing_user_delete(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
	):
		m_delete_permanently = mocker.patch.object(User, "delete_permanently")
		response: Response = admin_user_client.delete(
			self.endpoint,
			data={"users": [999]},
			format="json",
		)
		m_delete_permanently.assert_not_called()
		assert response.status_code == status.HTTP_200_OK
		assert response.data.get("failed_users") == 1

	def test_success(
		self,
		admin_user_client: APIClient,
		f_user_local: User,
	):
		response: Response = admin_user_client.delete(
			self.endpoint,
			data={"users": [f_user_local.id]},
			format="json",
		)
		assert response.status_code == status.HTTP_200_OK
		assert response.data.get("deleted_users") == 1
		assert not User.objects.filter(id=f_user_local.id).exists()


class TestBulkChangeStatus(BaseViewTestClass):
	_endpoint = "users-bulk-change-status"

	def test_raises_anti_lockout(
		self,
		mocker: MockerFixture,
		admin_user: User,
		admin_user_client: APIClient,
		f_log: MockType,
	):
		m_user_change_status = mocker.patch.object(
			UserViewSet, "user_change_status"
		)
		response: Response = admin_user_client.put(
			self.endpoint,
			data={
				"users": [admin_user.id],
				LOCAL_ATTR_ENABLED: True,
			},
			format="json",
		)

		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("code") == "user_anti_lockout"
		m_user_change_status.assert_not_called()
		f_log.assert_not_called()

	def test_raises_enabled_not_bool(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		f_log: MockType,
	):
		m_user_change_status = mocker.patch.object(
			UserViewSet, "user_change_status"
		)
		response: Response = admin_user_client.put(
			self.endpoint,
			data={
				"users": [999],
				LOCAL_ATTR_ENABLED: "somevalue",
			},
			format="json",
		)

		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert "must be of type bool" in response.data.get("detail")
		m_user_change_status.assert_not_called()
		f_log.assert_not_called()

	@pytest.mark.parametrize(
		("previous", "target", "expected"),
		(
			(
				True,
				True,
				True,
			),
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
		),
	)
	def test_success(
		self,
		admin_user: User,
		admin_user_client: APIClient,
		f_user_local: User,
		f_user_test: User,
		f_log: MockType,
		previous: bool,
		target: bool,
		expected: bool,
	):
		f_user_local.is_enabled = previous
		f_user_local.save()
		f_user_test.is_enabled = previous
		f_user_test.save()

		response: Response = admin_user_client.put(
			self.endpoint,
			data={
				"users": [f_user_local.id, f_user_test.id],
				LOCAL_ATTR_ENABLED: target,
			},
			format="json",
		)

		assert response.status_code == status.HTTP_200_OK
		assert response.data.get("updated_users") == 2
		f_user_local.refresh_from_db()
		assert f_user_local.is_enabled == expected
		f_user_test.refresh_from_db()
		assert f_user_test.is_enabled == expected
		f_log.call_count == 2
		for user in (f_user_test, f_user_local):
			f_log.assert_any_call(
				user=admin_user.id,
				operation_type=LOG_ACTION_UPDATE,
				log_target_class=LOG_CLASS_USER,
				log_target=user.username,
				message=LOG_EXTRA_ENABLE if target else LOG_EXTRA_DISABLE,
			)
