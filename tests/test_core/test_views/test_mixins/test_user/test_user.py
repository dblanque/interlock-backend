########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture, MockType

################################################################################
from core.views.mixins.user.main import UserMixin, AllUserMixins
from core.models.user import User, USER_TYPE_LDAP
from core.models.choices.log import LOG_CLASS_USER, LOG_ACTION_UPDATE
from core.exceptions.base import BadRequest
from core.exceptions.users import UserDoesNotExist, UserNotLocalType
from tests.test_core.test_views.conftest import UserFactory
from tests.test_core.conftest import (
	ConnectorFactory,
	LDAPConnectorMock,
	LDAPEntryFactoryProtocol,
)
from core.constants.attrs import *
from core.exceptions import users as exc_users


@pytest.fixture
def f_log(mocker: MockerFixture):
	return mocker.patch("core.views.mixins.user.main.DBLogMixin.log")


@pytest.fixture
def f_mixin():
	return UserMixin()


@pytest.fixture
def f_all_users_mixin():
	return AllUserMixins()


@pytest.fixture(autouse=True)
def f_ldap_connector(g_ldap_connector: ConnectorFactory):
	return g_ldap_connector(
		patch_path="core.views.mixins.user.main.LDAPConnector"
	)


class TestLocalUserExists:
	def test_username(self, f_mixin: UserMixin, f_user_local: User):
		with pytest.raises(exc_users.UserExists):
			f_mixin.local_user_exists(username=f_user_local.username)

	def test_email(self, f_mixin: UserMixin, f_user_local: User):
		with pytest.raises(exc_users.UserExists):
			f_mixin.local_user_exists(email=f_user_local.email)

	@pytest.mark.parametrize(
		"should_raise",
		(
			True,
			False,
		),
	)
	def test_username_and_email(
		self,
		should_raise: bool,
		f_mixin: UserMixin,
		f_user_local: User,
	):
		if should_raise:
			with pytest.raises(exc_users.UserExists):
				f_mixin.local_user_exists(
					username=f_user_local.username,
					email=f_user_local.email,
				)
		else:
			assert f_mixin.local_user_exists(
				username=f_user_local.username,
				email=f_user_local.email,
				raise_exception=False,
			)

	def test_raises_no_username_or_email(self, f_mixin: UserMixin):
		with pytest.raises(Exception, match="required"):
			f_mixin.local_user_exists(username=None, email=None)


class TestValidatedUserPkList:
	def test_success(self, f_mixin: UserMixin):
		m_users_pk_lst = [1, 2, 3, 4, 5]
		m_initial_data = {"users": m_users_pk_lst}
		assert f_mixin.validated_user_pk_list(m_initial_data) == m_users_pk_lst

	def test_raises_on_bad_inner_value(self, f_mixin: UserMixin):
		m_initial_data = {
			"users": [
				"somevalue",
				2,
				3,
				4,
			]
		}
		with pytest.raises(BadRequest):
			f_mixin.validated_user_pk_list(m_initial_data)

	@pytest.mark.parametrize(
		"value",
		(
			[],
			{"some": "dict"},
			False,
		),
	)
	def test_raises_on_bad_value(self, f_mixin: UserMixin, value):
		m_initial_data = {"users": value}
		with pytest.raises(BadRequest):
			f_mixin.validated_user_pk_list(m_initial_data)


@pytest.mark.django_db
class TestUserChangeStatus:
	@pytest.mark.parametrize(
		"previous_status, target_status, expected_status",
		(
			(True, True, True),
			(False, False, False),
			(False, True, True),
			(True, False, False),
		),
	)
	def test_success(
		self,
		f_mixin: UserMixin,
		user_factory: UserFactory,
		previous_status: bool,
		target_status: bool,
		expected_status: bool,
	):
		# Mock User
		m_user: User = user_factory(username="teststatuschange", email=None)
		m_user.is_enabled = previous_status
		m_user.save()

		f_mixin.user_change_status(m_user.id, target_status=target_status)

		m_user.refresh_from_db()
		assert m_user.is_enabled == expected_status

	def test_raises_not_exists(self, f_mixin: UserMixin):
		with pytest.raises(UserDoesNotExist):
			f_mixin.user_change_status(
				user_pk=999,
				target_status=True,
				raise_exception=True,
			)

	def test_returns_none_on_not_exists(self, f_mixin: UserMixin):
		assert (
			f_mixin.user_change_status(
				user_pk=999,
				target_status=True,
				raise_exception=False,
			)
			is None
		)

	def test_raises_not_local_user(
		self,
		f_mixin: UserMixin,
		user_factory: UserFactory,
	):
		m_user = user_factory(
			username="testraisesnotlocal",
			email=None,
			user_type=USER_TYPE_LDAP,
		)
		m_user.save()
		with pytest.raises(UserNotLocalType):
			f_mixin.user_change_status(m_user.pk, target_status=True)


@pytest.fixture
def f_index_map():
	return {
		0: LOCAL_ATTR_USERNAME,
		1: LOCAL_ATTR_EMAIL,
		2: LOCAL_ATTR_FIRST_NAME,
		3: LOCAL_ATTR_LAST_NAME,
	}


class TestBulkCreateFromCsv:
	def test_raises_row_length_mismatch(
		self,
		f_mixin: UserMixin,
		admin_user: User,
		f_index_map: dict,
	):
		with pytest.raises(exc_users.UserBulkInsertLengthError):
			f_mixin.bulk_create_from_csv(
				request_user=admin_user,
				user_rows=["an", "extra", "column"],
				index_map={0: LOCAL_ATTR_USERNAME, 1: LOCAL_ATTR_EMAIL},
			)

	@pytest.mark.django_db
	def test_serializer_error(
		self,
		f_mixin: UserMixin,
		admin_user: User,
		f_index_map: dict,
	):
		created, error = f_mixin.bulk_create_from_csv(
			request_user=admin_user,
			user_rows=[
				[
					"someuser",
					"someuser@example.com",
					"Some",
					False,
				]
			],
			index_map=f_index_map,
		)
		assert error == [
			{
				LOCAL_ATTR_USERNAME: "someuser",
				"stage": "serializer",
			}
		]
		assert not User.objects.filter(username="someuser").exists()

	@pytest.mark.django_db
	def test_save_error(
		self,
		mocker: MockerFixture,
		f_mixin: UserMixin,
		admin_user: User,
		f_index_map: dict,
	):
		m_save = mocker.patch.object(User, "save", side_effect=Exception)
		created, error = f_mixin.bulk_create_from_csv(
			request_user=admin_user,
			user_rows=[
				[
					"someuser",
					"someuser@example.com",
					"Some",
					"User",
				]
			],
			index_map=f_index_map,
		)
		m_save.assert_called_once()
		assert error == [
			{
				LOCAL_ATTR_USERNAME: "someuser",
				"stage": "save",
			}
		]
		assert not User.objects.filter(username="someuser").exists()

	@pytest.mark.django_db
	def test_success(
		self,
		f_mixin: UserMixin,
		admin_user: User,
		f_index_map: dict,
		f_log: MockType,
	):
		f_mixin.bulk_create_from_csv(
			request_user=admin_user,
			user_rows=[
				[
					"someuser",
					"someuser@example.com",
					"Some",
					"User",
				]
			],
			index_map=f_index_map,
		)
		assert User.objects.filter(username="someuser").exists()
		user_instance: User = User.objects.get(username="someuser")
		assert user_instance.email == "someuser@example.com"
		assert user_instance.first_name == "Some"
		assert user_instance.last_name == "User"
		assert not user_instance.check_password("")
		assert not user_instance.check_password(None)
		f_log.assert_called_once_with(
			user=admin_user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=user_instance.username,
		)


class TestBulkCreateFromDicts:
	def test_success(
		self,
		f_mixin: UserMixin,
		admin_user: User,
		f_log: MockType,
	):
		m_user_success = "someuser#1234"
		m_user_bad_email = "invaliduseremail"
		created, error = f_mixin.bulk_create_from_dicts(
			request_user=admin_user,
			user_dicts=[
				{
					LOCAL_ATTR_USERNAME: m_user_success,
					LOCAL_ATTR_EMAIL: "someuser@example.com",
					LOCAL_ATTR_FIRST_NAME: "Some",
					LOCAL_ATTR_LAST_NAME: "User",
				},
				{
					LOCAL_ATTR_USERNAME: m_user_bad_email,
					LOCAL_ATTR_EMAIL: False,
					LOCAL_ATTR_FIRST_NAME: "",
					LOCAL_ATTR_LAST_NAME: "",
				},
				{
					LOCAL_ATTR_USERNAME: "@-\\invalidusername",
					LOCAL_ATTR_EMAIL: "invaliduser@example.com",
					LOCAL_ATTR_FIRST_NAME: "",
					LOCAL_ATTR_LAST_NAME: "",
				},
			],
		)
		assert created == [m_user_success]
		assert error == [
			{
				LOCAL_ATTR_USERNAME: m_user_bad_email,
				"stage": "serializer",
			},
			{
				LOCAL_ATTR_USERNAME: 3,
				"stage": "serializer",
			},
		]

		assert User.objects.filter(username=m_user_success).exists()
		user_instance: User = User.objects.get(username=m_user_success)
		assert user_instance.email == "someuser@example.com"
		assert user_instance.first_name == "Some"
		assert user_instance.last_name == "User"
		assert not user_instance.check_password("")
		assert not user_instance.check_password(None)
		f_log.assert_called_once_with(
			user=admin_user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=user_instance.username,
		)

	def test_save_error(
		self,
		mocker: MockerFixture,
		f_mixin: UserMixin,
		admin_user: User,
		f_log: MockType,
	):
		m_save = mocker.patch.object(User, "save", side_effect=Exception)
		created, error = f_mixin.bulk_create_from_dicts(
			request_user=admin_user,
			user_dicts=[
				{
					LOCAL_ATTR_USERNAME: "someuser",
					LOCAL_ATTR_EMAIL: "someuser@example.com",
					LOCAL_ATTR_FIRST_NAME: "Some",
					LOCAL_ATTR_LAST_NAME: "User",
				},
			],
		)
		assert error == [
			{
				LOCAL_ATTR_USERNAME: "someuser",
				"stage": "save",
			}
		]
		m_save.assert_called_once()
		f_log.assert_not_called()


@pytest.mark.django_db
class TestCheckUserExists:
	def test_local_user(
		self,
		f_user_local: User,
		g_interlock_ldap_disabled,
		f_all_users_mixin: AllUserMixins,
		f_ldap_connector: LDAPConnectorMock,
	):
		with pytest.raises(exc_users.UserExists):
			assert f_all_users_mixin.check_user_exists(
				username=f_user_local.username,
				email=f_user_local.email,
			)

	def test_ldap_user(
		self,
		f_user_ldap: User,
		g_interlock_ldap_enabled,
		f_all_users_mixin: AllUserMixins,
		f_ldap_connector: LDAPConnectorMock,
		fc_ldap_entry: LDAPEntryFactoryProtocol,
	):
		f_ldap_connector.connection.entries = [
			fc_ldap_entry(
				spec=False,
				**{
					LDAP_ATTR_USERNAME_SAMBA_ADDS: f_user_ldap.username,
					LDAP_ATTR_EMAIL: f_user_ldap.email,
				},
			)
		]
		with pytest.raises(exc_users.UserExists):
			assert f_all_users_mixin.check_user_exists(
				username=f_user_ldap.username,
				email=f_user_ldap.email,
			)

	def test_ignore_local(
		self,
		f_user_local: User,
		g_interlock_ldap_enabled,
		f_all_users_mixin: AllUserMixins,
		f_ldap_connector: LDAPConnectorMock,
	):
		f_ldap_connector.connection.entries = []
		assert not f_all_users_mixin.check_user_exists(
			username=f_user_local.username,
			email=f_user_local.email,
			ignore_local=True,
		)

	def test_ignore_ldap(
		self,
		g_interlock_ldap_enabled,
		f_all_users_mixin: AllUserMixins,
		f_ldap_connector: LDAPConnectorMock,
		fc_ldap_entry: LDAPEntryFactoryProtocol,
	):
		# Mock existing LDAP User
		m_username = "someuser"
		m_email = "someemail@example.com"
		f_ldap_connector.connection.entries = [
			fc_ldap_entry(
				spec=False,
				**{
					LDAP_ATTR_USERNAME_SAMBA_ADDS: m_username,
					LDAP_ATTR_EMAIL: m_email,
				},
			)
		]

		assert not f_all_users_mixin.check_user_exists(
			username=m_username,
			email=m_email,
			ignore_ldap=True,
		)


class TestBulkCheckUsers:
	def test_raises_local_user(
		self,
		f_user_local: User,
		f_user_ldap: User,
		g_interlock_ldap_enabled,
		f_all_users_mixin: AllUserMixins,
		f_ldap_connector: LDAPConnectorMock,
		fc_ldap_entry: LDAPEntryFactoryProtocol,
	):
		f_ldap_connector.connection.entries = [
			fc_ldap_entry(
				spec=False,
				**{
					LDAP_ATTR_USERNAME_SAMBA_ADDS: f_user_ldap.username,
					LDAP_ATTR_EMAIL: f_user_ldap.email,
				},
			)
		]
		with pytest.raises(exc_users.UserExists):
			f_all_users_mixin.bulk_check_users(
				[
					(
						f_user_local.username,
						f_user_local.email,
					)
				]
			)

	def test_raises_ldap_user(
		self,
		f_user_ldap: User,
		g_interlock_ldap_enabled,
		f_all_users_mixin: AllUserMixins,
		f_ldap_connector: LDAPConnectorMock,
		fc_ldap_entry: LDAPEntryFactoryProtocol,
	):
		f_ldap_connector.connection.entries = [
			fc_ldap_entry(
				spec=False,
				**{
					LDAP_ATTR_USERNAME_SAMBA_ADDS: f_user_ldap.username,
					LDAP_ATTR_EMAIL: f_user_ldap.email,
				},
			)
		]
		with pytest.raises(exc_users.UserExists):
			f_all_users_mixin.bulk_check_users(
				[
					(
						f_user_ldap.username,
						f_user_ldap.email,
					)
				]
			)

	def test_returns_local_user_exists(
		self,
		f_user_local: User,
		f_all_users_mixin: AllUserMixins,
		f_ldap_connector: LDAPConnectorMock,
	):
		assert f_all_users_mixin.bulk_check_users(
			[
				(
					f_user_local.username,
					f_user_local.email,
				)
			],
			raise_exception=False,
		) == [f_user_local.username]

	def test_returns_ldap_user_exists(
		self,
		f_user_ldap: User,
		g_interlock_ldap_enabled,
		f_all_users_mixin: AllUserMixins,
		f_ldap_connector: LDAPConnectorMock,
		fc_ldap_entry: LDAPEntryFactoryProtocol,
	):
		f_ldap_connector.connection.entries = [
			fc_ldap_entry(
				spec=False,
				**{
					LDAP_ATTR_USERNAME_SAMBA_ADDS: f_user_ldap.username,
					LDAP_ATTR_EMAIL: f_user_ldap.email,
				},
			)
		]
		assert f_all_users_mixin.bulk_check_users(
			[
				(
					f_user_ldap.username,
					f_user_ldap.email,
				)
			],
			raise_exception=False,
		) == [f_user_ldap.username]

	def test_not_exists_success(
		self,
		f_all_users_mixin: AllUserMixins,
		f_ldap_connector: LDAPConnectorMock,
	):
		assert not f_all_users_mixin.bulk_check_users(
			[
				(
					"someuser",
					"someuser@example.com",
				),
			]
		)
