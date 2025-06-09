########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType
################################################################################
from core.views.mixins.user import UserMixin, AllUserMixins
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
from core.exceptions import (
	base as exc_base,
	users as exc_users,
)

@pytest.fixture
def f_log(mocker: MockerFixture):
	return mocker.patch("core.views.mixins.user.DBLogMixin.log")

@pytest.fixture
def f_mixin():
	return UserMixin()

@pytest.fixture(autouse=True)
def f_ldap_connector(g_ldap_connector: ConnectorFactory):
	return g_ldap_connector(patch_path="core.views.mixins.user.LDAPConnector")

@pytest.fixture
def f_all_users_mixin():
	return AllUserMixins()

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

class TestValidatedUserPkList():
	def test_success(self, f_mixin: UserMixin):
		m_users_pk_lst = [1,2,3,4,5]
		m_initial_data = {"users": m_users_pk_lst}
		assert f_mixin.validated_user_pk_list(
			m_initial_data) == m_users_pk_lst

	def test_raises_on_bad_inner_value(self, f_mixin: UserMixin):
		m_initial_data = {"users": ["somevalue", 2, 3, 4,]}
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
class TestUserChangeStatus():
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
		m_user: User = user_factory(
			username="teststatuschange", email=None)
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
		assert f_mixin.user_change_status(
			user_pk=999,
			target_status=True,
			raise_exception=False,
		) is None

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

class TestMapBulkCreateAttrs:

	def test_raises_missing_headers(self, f_mixin: UserMixin):
		with pytest.raises(exc_base.BadRequest) as e:
			f_mixin.map_bulk_create_attrs(headers=[], csv_map=None)
		assert "'headers' is required" in e.value.detail.get("detail")

	def test_raises_bad_csv_map_type(self, f_mixin: UserMixin):
		with pytest.raises(exc_base.BadRequest) as e:
			f_mixin.map_bulk_create_attrs(
				headers=[LOCAL_ATTR_USERNAME],
				csv_map="some_string",
			)
		assert "'csv_map' must be of type" in e.value.detail.get("detail")

	def test_raises_invalid_header_no_csv_map(self, f_mixin: UserMixin):
		with pytest.raises(exc_base.BadRequest) as e:
			f_mixin.map_bulk_create_attrs(["bad_header"])
		assert "existing local attributes" in e.value.detail.get("detail")

	def test_raises_invalid_header_with_csv_map(self, f_mixin: UserMixin):
		with pytest.raises(exc_base.BadRequest) as e:
			f_mixin.map_bulk_create_attrs(
				headers=["bad_header"],
				csv_map={"some_value": "bad_header"},
			)
		assert "existing local attributes" in e.value.detail.get("detail")

	def test_success_no_csv_map(self, f_mixin: UserMixin):
		result = f_mixin.map_bulk_create_attrs([
			LOCAL_ATTR_USERNAME,
			LOCAL_ATTR_EMAIL,
		])
		assert result == { 0: LOCAL_ATTR_USERNAME, 1: LOCAL_ATTR_EMAIL }

	def test_success_with_csv_map(self, f_mixin: UserMixin):
		result = f_mixin.map_bulk_create_attrs(
			headers=[
				"nombreusuario",
				"correo",
			],
			csv_map={
				LOCAL_ATTR_USERNAME: "nombreusuario",
				LOCAL_ATTR_EMAIL: "correo",
			}
		)
		assert result == { 0: LOCAL_ATTR_USERNAME, 1: LOCAL_ATTR_EMAIL }

class TestCleanupEmptyStrValues:
	def test_deletion(self, f_mixin: UserMixin):
		m_dct = {
			"a": "value",
			"b": "",
		}
		expected = m_dct.copy()
		expected.pop("b")
		assert f_mixin.cleanup_empty_str_values(m_dct) == expected

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
				user_rows=["an","extra","column"],
				index_map={
					0: LOCAL_ATTR_USERNAME,
					1: LOCAL_ATTR_EMAIL
				},
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
		assert error == 1
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
		assert error == 1
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
		created, error = f_mixin.bulk_create_from_dicts(
			request_user=admin_user,
			user_dicts=[
				{
					LOCAL_ATTR_USERNAME: "someuser",
					LOCAL_ATTR_EMAIL: "someuser@example.com",
					LOCAL_ATTR_FIRST_NAME: "Some",
					LOCAL_ATTR_LAST_NAME: "User",
				},
				{
					LOCAL_ATTR_USERNAME: "invaliduseremail",
					LOCAL_ATTR_EMAIL: False,
					LOCAL_ATTR_FIRST_NAME: "",
					LOCAL_ATTR_LAST_NAME: "",
				},
			]
		)
		assert created == 1
		assert error == 1

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
			]
		)
		assert error == 1
		m_save.assert_called_once()
		f_log.assert_not_called()

@pytest.mark.django_db
class TestGetLdapBackendEnabled:
	def test_enabled(self, f_all_users_mixin: AllUserMixins, g_interlock_ldap_enabled):
		f_all_users_mixin.get_ldap_backend_enabled()
		assert f_all_users_mixin.ldap_backend_enabled

	def test_disabled(self, f_all_users_mixin: AllUserMixins, g_interlock_ldap_disabled):
		f_all_users_mixin.get_ldap_backend_enabled()
		assert not f_all_users_mixin.ldap_backend_enabled

	def test_disabled_on_not_exists(self, f_all_users_mixin: AllUserMixins):
		f_all_users_mixin.get_ldap_backend_enabled()
		assert not f_all_users_mixin.ldap_backend_enabled

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
			fc_ldap_entry(spec=False, **{
				LDAP_ATTR_USERNAME_SAMBA_ADDS: f_user_ldap.username,
				LDAP_ATTR_EMAIL: f_user_ldap.email,
			})	
		]
		with pytest.raises(exc_users.UserExists):
			assert f_all_users_mixin.check_user_exists(
				username=f_user_ldap.username,
				email=f_user_ldap.email,
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
			fc_ldap_entry(spec=False, **{
				LDAP_ATTR_USERNAME_SAMBA_ADDS: f_user_ldap.username,
				LDAP_ATTR_EMAIL: f_user_ldap.email,
			})	
		]
		with pytest.raises(exc_users.UserExists):
			f_all_users_mixin.bulk_check_users(
				[(f_user_local.username, f_user_local.email,)]
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
			fc_ldap_entry(spec=False, **{
				LDAP_ATTR_USERNAME_SAMBA_ADDS: f_user_ldap.username,
				LDAP_ATTR_EMAIL: f_user_ldap.email,
			})	
		]
		with pytest.raises(exc_users.UserExists):
			f_all_users_mixin.bulk_check_users(
				[(f_user_ldap.username, f_user_ldap.email,)]
			)

	def test_returns_local_user_exists(
		self,
		f_user_local: User,
		f_all_users_mixin: AllUserMixins,
		f_ldap_connector: LDAPConnectorMock,
	):
		assert f_all_users_mixin.bulk_check_users(
			[(f_user_local.username, f_user_local.email,)],
			raise_exception=False,
		)

	def test_returns_ldap_user_exists(
		self,
		f_user_ldap: User,
		g_interlock_ldap_enabled,
		f_all_users_mixin: AllUserMixins,
		f_ldap_connector: LDAPConnectorMock,
		fc_ldap_entry: LDAPEntryFactoryProtocol,
	):
		f_ldap_connector.connection.entries = [
			fc_ldap_entry(spec=False, **{
				LDAP_ATTR_USERNAME_SAMBA_ADDS: f_user_ldap.username,
				LDAP_ATTR_EMAIL: f_user_ldap.email,
			})	
		]
		assert f_all_users_mixin.bulk_check_users(
			[(f_user_ldap.username, f_user_ldap.email,)],
			raise_exception=False,
		)

	def test_not_exists_success(
		self,
		f_all_users_mixin: AllUserMixins,
		f_ldap_connector: LDAPConnectorMock,
	):
		assert not f_all_users_mixin.bulk_check_users(
			[
				("someuser", "someuser@example.com",),
			]
		)