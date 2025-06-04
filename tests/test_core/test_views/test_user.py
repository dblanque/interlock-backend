########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType

################################################################################
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework import status
from core.models.user import User
from core.exceptions.ldap import LDAPObjectExists
from tests.test_core.test_views.conftest import UserFactory
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
)
from core.models.choices.log import (
	LOG_CLASS_USER,
	LOG_ACTION_CREATE,
	LOG_ACTION_UPDATE,
	LOG_ACTION_READ,
	LOG_ACTION_DELETE,
)

@pytest.fixture(autouse=True)
def f_ldap_connector(g_ldap_connector: ConnectorFactory):
	return g_ldap_connector(patch_path="core.views.user.LDAPConnector")

@pytest.fixture
def f_user_test(user_factory: UserFactory) -> User:
	return user_factory(
		username="mock_user",
		email="mockuser@example.com",
	)


class TestList:
	endpoint = reverse("users-list")

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


class TestInsert:
	endpoint = reverse("users-insert")

	def test_success_with_ldap_disabled(
		self,
		admin_user_client: APIClient,
		mocker: MockerFixture,
		g_interlock_ldap_disabled,
	):
		m_data = {
			LOCAL_ATTR_USERNAME: "new_user",
			LOCAL_ATTR_PASSWORD: "mockpassword",
			LOCAL_ATTR_PASSWORD_CONFIRM: "mockpassword",
			LOCAL_ATTR_EMAIL: "new@example.com",
			LOCAL_ATTR_IS_ENABLED: True,
		}
		m_log = mocker.patch("core.views.user.DBLogMixin.log")
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
		assert user.check_password(m_data[LOCAL_ATTR_PASSWORD])

		# Verify logging
		m_log.assert_called_once_with(
			user=mocker.ANY,  # request.user.id
			operation_type=LOG_ACTION_CREATE,
			log_target_class=LOG_CLASS_USER,
			log_target=m_data[LOCAL_ATTR_USERNAME],
		)

	def test_success_with_ldap_enabled(
		self,
		f_ldap_connector: LDAPConnectorMock,
		admin_user_client: APIClient,
		mocker: MockerFixture,
		g_interlock_ldap_enabled,
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
		m_log = mocker.patch("core.views.user.DBLogMixin.log")

		# Act
		response: Response = admin_user_client.post(self.endpoint, user_data)

		# Assert
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
		m_log.assert_called_once_with(
			user=mocker.ANY,
			operation_type=LOG_ACTION_CREATE,
			log_target_class=LOG_CLASS_USER,
			log_target=user_data[LOCAL_ATTR_USERNAME],
		)

	def test_serializer_validation_failure(
		self,
		admin_user_client: APIClient,
		mocker: MockerFixture,
	):
		"""Test invalid payload returns BadRequest"""
		invalid_data = {
			LOCAL_ATTR_USERNAME: "someuser",
			LOCAL_ATTR_EMAIL: "invalid-email",
			# Missing password
		}
		m_ldap_user_exists = mocker.patch(
			"core.views.user.UserViewSet.ldap_user_exists"
		)

		# Act
		response: Response = admin_user_client.post(self.endpoint, invalid_data)

		# Assert
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		m_ldap_user_exists.assert_not_called()
		assert "errors" in response.data
		assert LOCAL_ATTR_PASSWORD in response.data["errors"]
		assert LOCAL_ATTR_EMAIL in response.data["errors"]

	def test_ldap_user_exists_raises_error(
		self,
		admin_user_client: APIClient,
		mocker: MockerFixture,
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

# class TestFetch:
# 	endpoint = reverse("users-fetch")

# class TestUpdate:
# 	endpoint = reverse("users-update")

# class TestDelete:
# 	endpoint = reverse("users-delete")

# class TestChangeStatus:
# 	endpoint = reverse("users-change-status")

# class TestChangePassword:
# 	endpoint = reverse("users-change-password")

# class TestSelfChangePassword:
# 	endpoint = reverse("users-self-change-password")

# class TestSelfUpdate:
# 	endpoint = reverse("users-self-update")
