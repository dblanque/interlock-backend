########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType

################################################################################
from core.views.mixins.logs import LogMixin
from core.views.mixins.ldap.user import LDAPUserMixin
from core.ldap.defaults import LDAP_DOMAIN
from rest_framework.serializers import ValidationError
from core.models.user import User
from typing import Union, Protocol, overload
from ldap3 import MODIFY_REPLACE
from core.utils.main import getldapattrvalue, getlocalkeyforldapattr
from django.core.exceptions import ObjectDoesNotExist
from datetime import datetime
from core.models.choices.log import (
	LOG_ACTION_DELETE,
	LOG_ACTION_READ,
	LOG_ACTION_UPDATE,
	LOG_ACTION_CREATE,
	LOG_TARGET_ALL,
	LOG_CLASS_USER,
	LOG_EXTRA_ENABLE,
	LOG_EXTRA_DISABLE,
	LOG_EXTRA_UNLOCK,
)
from core.ldap.types.account import LDAPAccountTypes
from core.ldap.adsi import (
	LDAP_PERMS,
	LDAP_UF_LOCKOUT,
	LDAP_UF_ACCOUNT_DISABLE,
	LDAP_UF_DONT_EXPIRE_PASSWD,
	LDAP_UF_NORMAL_ACCOUNT,
	calc_permissions,
)
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from core.exceptions import (
	users as exc_user,
	ldap as exc_ldap,
)
from core.ldap.filter import LDAPFilter
from core.models.ldap_object import LDAPObject, LDAPObjectTypes
from ldap3 import Entry as LDAPEntry
from ldap3.extend import (
	ExtendedOperationsRoot,
	StandardExtendedOperations,
	MicrosoftExtendedOperations,
)
from core.constants.attrs import *
from tests.test_core.conftest import (
	RuntimeSettingsFactory,
	LDAPEntryFactoryProtocol,
)
from django.utils import timezone as tz


@pytest.fixture
def f_user_mixin(mocker):
	mixin = LDAPUserMixin()
	mixin.ldap_connection = mocker.MagicMock()
	mixin.request = mocker.MagicMock()
	mixin.request.user.id = 1
	return mixin


@pytest.fixture(autouse=True)
def f_log_mixin(mocker):
	mock = mocker.patch(
		"core.views.mixins.ldap.user.DBLogMixin", mocker.MagicMock()
	)
	return mock


@pytest.fixture(autouse=True)
def f_runtime_settings(g_runtime_settings: RuntimeSettingsFactory):
	return g_runtime_settings("core.views.mixins.ldap.user.RuntimeSettings")


@pytest.fixture
def _fld(f_runtime_settings: RuntimeSettingsSingleton):
	def maker(v):
		return f_runtime_settings.LDAP_FIELD_MAP[v]

	return maker


@pytest.fixture
def f_auth_field_username(_fld):
	return _fld(LOCAL_ATTR_USERNAME)


@pytest.fixture
def f_auth_field_email(_fld):
	return _fld(LOCAL_ATTR_EMAIL)


@pytest.fixture
def f_ldap_domain(f_runtime_settings: RuntimeSettingsSingleton):
	return f_runtime_settings.LDAP_DOMAIN


@pytest.fixture
def f_ldap_search_base(f_runtime_settings: RuntimeSettingsSingleton):
	return f_runtime_settings.LDAP_AUTH_SEARCH_BASE


@pytest.fixture
def fc_user_permissions():
	def maker(permissions: list = None) -> int:
		if not permissions:
			permissions = [LDAP_UF_DONT_EXPIRE_PASSWD, LDAP_UF_NORMAL_ACCOUNT]
		i = 0
		for p in permissions:
			i = i + LDAP_PERMS[p]["value"]
		return i

	return maker


@pytest.fixture
def f_default_user_filter(f_runtime_settings: RuntimeSettingsSingleton):
	def maker(username):
		_filter = LDAPFilter.and_(
			LDAPFilter.eq(
				LDAP_ATTR_OBJECT_CLASS,
				f_runtime_settings.LDAP_AUTH_OBJECT_CLASS,
			),
			LDAPFilter.not_(LDAPFilter.eq(LDAP_ATTR_OBJECT_CLASS, "computer")),
			LDAPFilter.eq(LDAP_ATTR_USERNAME_SAMBA_ADDS, username),
		).to_string()
		return _filter

	return maker


class LDAPUserEntryFactory(Protocol):
	@overload
	def __call__(self, spec=False, **kwargs) -> LDAPEntry: ...

	def __call__(
		self, username="testuser", spec=False, **kwargs
	) -> LDAPEntry: ...

	def __call__(self, username="testuser", **kwargs) -> LDAPEntry: ...


@pytest.fixture
def fc_user_entry(
	mocker: MockerFixture,
	fc_ldap_entry: LDAPEntryFactoryProtocol,
	f_ldap_search_base,
	_fld,
	f_ldap_domain,
) -> LDAPUserEntryFactory:
	def maker(username="testuser", **kwargs):
		with_spec = kwargs.pop("spec", False)
		if with_spec:
			spec_cls = LDAPEntry
		else:
			spec_cls = None
		attrs = {
			_fld(LOCAL_ATTR_USERNAME): username,
			_fld(LOCAL_ATTR_EMAIL): f"{username}@{f_ldap_domain}",
			_fld(LOCAL_ATTR_DN): f"CN={username},CN=Users,{f_ldap_search_base}",
			_fld(LOCAL_ATTR_FIRST_NAME): "Test",
			_fld(LOCAL_ATTR_LAST_NAME): "User",
			_fld(LOCAL_ATTR_INITIALS): "TU",
		} | kwargs
		return fc_ldap_entry(spec=spec_cls, **attrs)

	return maker


@pytest.fixture
def f_ldap_object(mocker: MockerFixture):
	def maker(entry: LDAPEntry):
		m_ldap_object: Union[MockType, LDAPObject] = mocker.MagicMock()
		m_ldap_object.entry = entry
		m_ldap_object.attributes = {}
		for attr in entry.entry_attributes:
			_field = getlocalkeyforldapattr(attr)
			m_ldap_object.attributes[_field] = getldapattrvalue(entry, attr)
		return m_ldap_object

	return maker


@pytest.fixture
def f_group_dn(f_ldap_search_base):
	return f"CN=testgroup,OU=Groups,{f_ldap_search_base}"


@pytest.fixture
def f_ldap_user_instance(mocker: MockerFixture):
	return mocker.Mock(name="f_ldap_user_instance")


@pytest.fixture
def f_ldap_user_cls(mocker: MockerFixture, f_ldap_user_instance):
	return mocker.patch(
		"core.views.mixins.ldap.user.LDAPUser",
		return_value=f_ldap_user_instance,
	)

class TestIsBuiltinUser:
	@pytest.mark.parametrize(
		"username, sid, ignore_admin, expected",
		(
			("Administrator", None, False, True),
			(None, "S-1-5-1234-500", False, True),
			("Administrator", None, True, False),
			(None, "S-1-5-1234-500", True, False),
			("Guest", None, False, True),
			(None, "S-1-5-1234-501", False, True),
			("Guest", "S-1-5-1234-501", True, True),
			("krbtgt", None, False, True),
			(None, "S-1-5-1234-502", False, True),
			("krbtgt", "S-1-5-1234-502", True, True),
			("TestUser", None, False, False),
			(None, "S-1-5-1234-1234", False, False),
		),
	)
	def test_success(
		self,
		f_user_mixin: LDAPUserMixin,
		username: str,
		sid: str,
		ignore_admin: bool,
		expected: bool,
	):
		assert f_user_mixin.is_built_in_user(
			username=username,
			security_id=sid,
			ignore_admin=ignore_admin,
		) == expected

class TestGetUserObjectFilter:
	def test_xor_raises(self, f_user_mixin: LDAPUserMixin):
		with pytest.raises(ValueError, match="single value"):
			f_user_mixin.get_user_object_filter(username="a", email="b")

	def test_xor_match_raises(self, f_user_mixin: LDAPUserMixin):
		with pytest.raises(ValueError, match="incompatible"):
			f_user_mixin.get_user_object_filter(username="a", match_both=True)

	@pytest.mark.parametrize(
		"username, email, exclude_computers, expected",
		(
			(
				"testuser",
				None,
				False,
				"(&(objectClass=person)(sAMAccountName=testuser))",
			),
			(
				"testuser",
				None,
				True,
				"(&(objectClass=person)(!(objectClass=computer))(sAMAccountName=testuser))",
			),
			(
				None,
				f"testuser@{LDAP_DOMAIN}",
				False,
				f"(&(objectClass=person)(mail=testuser@{LDAP_DOMAIN}))",
			),
			(
				None,
				f"testuser@{LDAP_DOMAIN}",
				True,
				f"(&(objectClass=person)(!(objectClass=computer))(mail=testuser@{LDAP_DOMAIN}))",
			),
		),
	)
	def test_with_xor(
		self,
		username: str,
		email: str,
		exclude_computers: bool,
		expected: str,
		f_user_mixin: LDAPUserMixin,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		f_runtime_settings.EXCLUDE_COMPUTER_ACCOUNTS = exclude_computers
		assert (
			f_user_mixin.get_user_object_filter(username=username, email=email)
			== expected
		)

	@pytest.mark.parametrize(
		"username, email, exclude_computers, match_both, expected",
		(
			(
				"testuser",
				f"testuser@{LDAP_DOMAIN}",
				False,
				False,
				f"(&(objectClass=person)(|(sAMAccountName=testuser)(mail=testuser@{LDAP_DOMAIN})))",
			),
			(
				"testuser",
				f"testuser@{LDAP_DOMAIN}",
				True,
				False,
				f"(&(objectClass=person)(!(objectClass=computer))(|(sAMAccountName=testuser)(mail=testuser@{LDAP_DOMAIN})))",
			),
			(
				"testuser",
				f"testuser@{LDAP_DOMAIN}",
				False,
				True,
				f"(&(objectClass=person)(&(sAMAccountName=testuser)(mail=testuser@{LDAP_DOMAIN})))",
			),
			(
				"testuser",
				f"testuser@{LDAP_DOMAIN}",
				True,
				True,
				f"(&(objectClass=person)(!(objectClass=computer))(&(sAMAccountName=testuser)(mail=testuser@{LDAP_DOMAIN})))",
			),
		),
	)
	def test_without_xor(
		self,
		username: str,
		email: str,
		exclude_computers: bool,
		match_both: bool,
		expected: str,
		f_user_mixin: LDAPUserMixin,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		f_runtime_settings.EXCLUDE_COMPUTER_ACCOUNTS = exclude_computers
		assert (
			f_user_mixin.get_user_object_filter(
				username=username, email=email, xor=False, match_both=match_both
			)
			== expected
		)


class TestGetUserEntry:
	def test_raises_value_error(self, f_user_mixin: LDAPUserMixin):
		with pytest.raises(ValueError):
			f_user_mixin.get_user_entry()

	def test_raises_not_found(self, f_user_mixin: LDAPUserMixin):
		with pytest.raises(exc_user.UserEntryNotFound):
			f_user_mixin.get_user_entry(
				username="testuser", raise_if_not_exists=True
			)

	def test_returns_none(self, f_user_mixin: LDAPUserMixin):
		assert f_user_mixin.get_user_entry(username="testuser") is None

	def test_no_entries(self, f_user_mixin: LDAPUserMixin):
		f_user_mixin.ldap_connection.entries = []
		assert f_user_mixin.get_user_entry(username="some_user") is None


class TestGetUserObject:
	@pytest.mark.parametrize(
		"username, email",
		(
			(
				"testuser",
				None,
			),
			(
				None,
				f"testuser@{LDAP_DOMAIN}",
			),
			(
				"testuser",
				f"testuser@{LDAP_DOMAIN}",
			),
		),
	)
	def test_success(
		self,
		mocker: MockerFixture,
		username,
		email,
		_fld,
		f_user_mixin: LDAPUserMixin,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		m_entry = mocker.Mock()
		setattr(
			m_entry,
			_fld(LOCAL_ATTR_USERNAME),
			username,
		)
		setattr(
			m_entry,
			_fld(LOCAL_ATTR_EMAIL),
			email,
		)
		f_user_mixin.ldap_connection.entries = [m_entry]

		m_get_user_entry = mocker.patch.object(f_user_mixin, "get_user_entry")
		f_user_mixin.get_user_object(username=username, email=email)
		f_user_mixin.ldap_connection.search.assert_called_once()
		m_get_user_entry.assert_called_once_with(username=username, email=email)

	def test_raises(self, f_user_mixin: LDAPUserMixin):
		with pytest.raises(ValidationError):
			f_user_mixin.get_user_object()


class TestDunderGetAllLdapUsers:
	@pytest.fixture
	def expected_search_filter(
		self, _fld, f_runtime_settings: RuntimeSettingsSingleton
	):
		_flt = LDAPFilter.and_(
			LDAPFilter.eq(
				_fld(LOCAL_ATTR_OBJECT_CLASS),
				f_runtime_settings.LDAP_AUTH_OBJECT_CLASS,
			),
			LDAPFilter.not_(
				LDAPFilter.eq(
					_fld(LOCAL_ATTR_OBJECT_CLASS),
					"computer",
				)
			),
			LDAPFilter.not_(
				LDAPFilter.eq(
					_fld(LOCAL_ATTR_OBJECT_CLASS),
					"contact",
				)
			),
		).to_string()
		return _flt

	@pytest.fixture
	def expected_search_attrs(self, _fld):
		return [
			_fld(LOCAL_ATTR_FIRST_NAME),
			_fld(LOCAL_ATTR_LAST_NAME),
			_fld(LOCAL_ATTR_FULL_NAME),
			_fld(LOCAL_ATTR_USERNAME),
			_fld(LOCAL_ATTR_EMAIL),
			_fld(LOCAL_ATTR_DN),
			_fld(LOCAL_ATTR_UAC),
		]

	def test_success_as_list_of_dict(
		self,
		_fld,
		fc_user_entry: LDAPUserEntryFactory,
		f_user_mixin: LDAPUserMixin,
		f_runtime_settings: RuntimeSettingsSingleton,
		expected_search_filter,
		expected_search_attrs,
	):
		m_entries = [
			fc_user_entry(username="test1", spec=True),
			fc_user_entry(
				username="test2",
				spec=True,
				**{
					_fld(LOCAL_ATTR_UAC): calc_permissions(
						[
							LDAP_UF_NORMAL_ACCOUNT,
							LDAP_UF_DONT_EXPIRE_PASSWD,
						]
					)
				},
			),
			fc_user_entry(
				username="test3",
				spec=True,
				**{
					_fld(LOCAL_ATTR_UAC): calc_permissions(
						[
							LDAP_UF_ACCOUNT_DISABLE,
							LDAP_UF_NORMAL_ACCOUNT,
							LDAP_UF_DONT_EXPIRE_PASSWD,
						]
					)
				},
			),
		]
		f_user_mixin.ldap_connection.entries = m_entries

		# Assert
		result = f_user_mixin._get_all_ldap_users(as_entries=False)
		f_user_mixin.ldap_connection.search.assert_called_once_with(
			search_base=f_runtime_settings.LDAP_AUTH_SEARCH_BASE,
			search_filter=expected_search_filter,
			attributes=expected_search_attrs,
		)
		for idx, user in enumerate(result):
			expected_keys = {
				LOCAL_ATTR_DN,
				LOCAL_ATTR_USERNAME,
				LOCAL_ATTR_NAME,
				LOCAL_ATTR_TYPE,
				LOCAL_ATTR_EMAIL,
				LOCAL_ATTR_FIRST_NAME,
				LOCAL_ATTR_LAST_NAME,
				LOCAL_ATTR_INITIALS,
			}
			if LOCAL_ATTR_IS_ENABLED in user:
				expected_keys.add(LOCAL_ATTR_IS_ENABLED)
			assert set(user.keys()) == expected_keys
			assert user[LOCAL_ATTR_TYPE] == LDAPObjectTypes.USER.name.lower()
			assert user[LOCAL_ATTR_USERNAME] == getldapattrvalue(
				m_entries[idx], _fld(LOCAL_ATTR_USERNAME)
			)
		assert result[1][LOCAL_ATTR_IS_ENABLED]
		assert not result[2][LOCAL_ATTR_IS_ENABLED]

	def test_success_as_list_of_entries(
		self,
		fc_user_entry: LDAPUserEntryFactory,
		f_user_mixin: LDAPUserMixin,
		f_runtime_settings: RuntimeSettingsSingleton,
		expected_search_filter,
		expected_search_attrs,
	):
		m_entries = [
			fc_user_entry(username="test1", spec=True),
			fc_user_entry(username="test2", spec=True),
			fc_user_entry(username="test3", spec=True),
		]
		f_user_mixin.ldap_connection.entries = m_entries

		# Assert
		result = f_user_mixin._get_all_ldap_users(as_entries=True)
		f_user_mixin.ldap_connection.search.assert_called_once_with(
			search_base=f_runtime_settings.LDAP_AUTH_SEARCH_BASE,
			search_filter=expected_search_filter,
			attributes=expected_search_attrs,
		)
		assert result == m_entries


class TestList:
	def test_success(
		self,
		mocker: MockerFixture,
		f_user_mixin: LDAPUserMixin,
		f_log_mixin: LogMixin,
	):
		m_result = [
			{"username": "user1"},
			{"username": "user2"},
		]
		m_get_all_ldap_users = mocker.patch.object(
			f_user_mixin,
			"_get_all_ldap_users",
			mocker.Mock(return_value=m_result),
		)
		result = f_user_mixin.ldap_user_list()
		m_get_all_ldap_users.assert_called_once()
		f_log_mixin.log.assert_called_once_with(
			user=1,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_USER,
			log_target=LOG_TARGET_ALL,
		)
		assert "users" in result
		assert "headers" in result
		assert result["users"] == m_result
		assert result["headers"] == (
			LOCAL_ATTR_USERNAME,
			LOCAL_ATTR_FIRST_NAME,
			LOCAL_ATTR_LAST_NAME,
			LOCAL_ATTR_EMAIL,
			LOCAL_ATTR_IS_ENABLED,
		)


class TestInsert:
	@pytest.mark.parametrize(
		"path, exclude_keys",
		(
			(
				None,
				[],
			),
			(
				"OU=Test,DC=example,DC=com",
				[LOCAL_ATTR_ADDRESS],
			),
		),
	)
	def test_success(
		self,
		path,
		exclude_keys: list[str],
		mocker: MockerFixture,
		f_runtime_settings: RuntimeSettingsSingleton,
		f_user_mixin: LDAPUserMixin,
		f_log_mixin: LogMixin,
	):
		# Mock LDAPUser class
		m_ldap_user = mocker.Mock()
		m_ldap_user_cls = mocker.Mock(return_value=m_ldap_user)
		mocker.patch("core.views.mixins.ldap.user.LDAPUser", m_ldap_user_cls)
		m_data = {
			LOCAL_ATTR_USERNAME: "testuser",
			LOCAL_ATTR_ADDRESS: "some_address",
			LOCAL_ATTR_PATH: path,
		}
		expected_data = m_data.copy()
		expected_data.pop(LOCAL_ATTR_PATH, None)
		for ek in exclude_keys:
			expected_data.pop(ek, None)

		f_user_mixin.ldap_user_insert(
			data=m_data,
			exclude_keys=exclude_keys,
		)
		m_ldap_user_cls.assert_called_once_with(
			connection=f_user_mixin.ldap_connection,
			distinguished_name="CN=testuser,CN=Users,%s"
			% (f_runtime_settings.LDAP_AUTH_SEARCH_BASE)
			if not path
			else "CN=testuser,%s" % (path),
			attributes=expected_data,
		)
		m_ldap_user.save.assert_called_once()
		f_log_mixin.log.assert_called_once_with(
			user=1,
			operation_type=LOG_ACTION_CREATE,
			log_target_class=LOG_CLASS_USER,
			log_target="testuser",
		)

	def test_dn_raises_exception(
		self,
		mocker: MockerFixture,
		f_runtime_settings: RuntimeSettingsSingleton,
		f_user_mixin: LDAPUserMixin,
		f_log_mixin: LogMixin,
	):
		# Mock LDAPUser class
		m_ldap_user_cls = mocker.Mock()
		mocker.patch("core.views.mixins.ldap.user.LDAPUser", m_ldap_user_cls)
		# Mock safe_dn to return exc
		mocker.patch(
			"core.views.mixins.ldap.user.safe_dn", side_effect=Exception
		)
		m_data = {
			LOCAL_ATTR_USERNAME: "testuser",
			LOCAL_ATTR_ADDRESS: "some_address",
		}

		with pytest.raises(exc_user.UserDNPathException):
			f_user_mixin.ldap_user_insert(data=m_data)
		m_ldap_user_cls.assert_not_called()
		f_log_mixin.log.assert_not_called()

	def test_raises_exception(
		self,
		mocker: MockerFixture,
		f_runtime_settings: RuntimeSettingsSingleton,
		f_user_mixin: LDAPUserMixin,
		f_log_mixin: LogMixin,
	):
		# Mock LDAPUser class
		m_ldap_user = mocker.Mock()
		m_ldap_user_cls = mocker.Mock(
			return_value=m_ldap_user,
			side_effect=Exception,
		)
		mocker.patch("core.views.mixins.ldap.user.LDAPUser", m_ldap_user_cls)
		m_data = {
			LOCAL_ATTR_USERNAME: "testuser",
			LOCAL_ATTR_ADDRESS: "some_address",
		}
		expected_data = m_data.copy()
		expected_data.pop(LOCAL_ATTR_PATH, None)

		with pytest.raises(exc_user.UserCreate):
			f_user_mixin.ldap_user_insert(data=m_data, return_exception=True)
		m_ldap_user_cls.assert_called_once_with(
			connection=f_user_mixin.ldap_connection,
			distinguished_name="CN=testuser,CN=Users,%s"
			% (f_runtime_settings.LDAP_AUTH_SEARCH_BASE),
			attributes=expected_data,
		)
		m_ldap_user.save.assert_not_called()
		f_log_mixin.log.assert_not_called()


class TestUpdate:
	def test_success(
		self,
		mocker: MockerFixture,
		normal_user: User,
		f_user_mixin: LDAPUserMixin,
		f_log_mixin: LogMixin,
	):
		m_email_update = "another@example.com"
		# Mock LDAPUser class
		m_ldap_user = mocker.Mock()
		m_ldap_user.attributes = {"old": "attributes"}
		m_ldap_user_cls = mocker.Mock(return_value=m_ldap_user)
		mocker.patch("core.views.mixins.ldap.user.LDAPUser", m_ldap_user_cls)
		m_data = {
			LOCAL_ATTR_USERNAME: normal_user.username,
			LOCAL_ATTR_EMAIL: m_email_update,
		}

		f_user_mixin.ldap_user_update(data=m_data)
		m_ldap_user_cls.assert_called_once_with(
			connection=f_user_mixin.ldap_connection,
			username=normal_user.username,
		)
		m_ldap_user.attributes = m_data
		m_ldap_user.save.assert_called_once()
		f_log_mixin.log.assert_called_once_with(
			user=1,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=normal_user.username,
		)
		normal_user.refresh_from_db()
		assert normal_user.email == m_email_update

	def test_success_no_local_user(
		self,
		mocker: MockerFixture,
		f_user_mixin: LDAPUserMixin,
		f_log_mixin: LogMixin,
	):
		m_username = "testuser"
		m_email_update = "another@example.com"
		# Mock LDAPUser class
		m_user_instance = mocker.Mock()
		m_user_instance.attributes = {"old": "attributes"}
		m_ldap_user_cls = mocker.Mock(return_value=m_user_instance)
		mocker.patch("core.views.mixins.ldap.user.LDAPUser", m_ldap_user_cls)
		m_data = {
			LOCAL_ATTR_USERNAME: m_username,
			LOCAL_ATTR_EMAIL: m_email_update,
		}
		# Mock User class
		m_user_cls = mocker.patch("core.views.mixins.ldap.user.User")
		m_user_cls.objects.get.side_effect = ObjectDoesNotExist

		f_user_mixin.ldap_user_update(data=m_data)
		m_ldap_user_cls.assert_called_once_with(
			connection=f_user_mixin.ldap_connection, username=m_username
		)
		m_user_instance.attributes = m_data
		m_user_instance.save.assert_called_once()
		f_log_mixin.log.assert_called_once_with(
			user=1,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=m_username,
		)
		m_user_cls.save.assert_not_called()


class TestSetLdapPassword:
	@pytest.mark.parametrize(
		"user_dn, user_pwd_new, user_pwd_old, exc_match",
		(
			(  # Bad user_dn
				None,  # user_dn
				None,  # user_pwd_new
				None,  # user_pwd_old
				"user_dn must be of type str",
			),
			(  # Bad user_pwd_new
				"mock_dn",  # user_dn
				None,  # user_pwd_new
				None,  # user_pwd_old
				"user_pwd_new must be of type str",
			),
			(  # Bad user_pwd_old
				"mock_dn",  # user_dn
				"mock_pwd_new",  # user_pwd_new
				None,  # user_pwd_old
				"user_pwd_old must be of type str",
			),
		),
		ids=[
			"TypeError raised for bad user_dn",
			"TypeError raised for bad user_pwd_new",
			"TypeError raised for bad user_pwd_old",
		],
	)
	def test_raises_type_error(
		self,
		f_user_mixin: LDAPUserMixin,
		user_dn: str,
		user_pwd_new: str,
		user_pwd_old: str,
		exc_match: str,
	):
		with pytest.raises(TypeError, match=exc_match):
			f_user_mixin.ldap_set_password(
				user_dn=user_dn,
				user_pwd_new=user_pwd_new,
				user_pwd_old=user_pwd_old,
			)

	def test_raises_value_error(self, f_user_mixin: LDAPUserMixin):
		with pytest.raises(ValueError):
			f_user_mixin.ldap_set_password(
				user_dn="mock_dn", user_pwd_new="", set_by_admin=True
			)

	def test_raises_pwds_dont_match(self, f_user_mixin: LDAPUserMixin):
		with pytest.raises(exc_user.UserOldPasswordRequired):
			f_user_mixin.ldap_set_password(
				user_dn="mock_dn",
				user_pwd_new="new_pwd",
				user_pwd_old="",
			)

	def test_adds_raises(
		self, mocker: MockerFixture, f_user_mixin: LDAPUserMixin
	):
		m_logger = mocker.patch("core.views.mixins.ldap.user.logger")
		extended_operations: ExtendedOperationsRoot = (
			f_user_mixin.ldap_connection.extend
		)
		eo_standard: StandardExtendedOperations = extended_operations.standard
		eo_standard.modify_password.side_effect = Exception

		f_user_mixin.ldap_connection.server.info.supported_extensions = [
			"1.3.6.1.4.1.4203.1.11.1"
		]
		m_distinguished_name = "mock_dn"
		with pytest.raises(exc_user.UserUpdateError):
			f_user_mixin.ldap_set_password(
				user_dn=m_distinguished_name,
				user_pwd_new="new_pwd",
				set_by_admin=True,
			)
		eo_standard.modify_password.assert_called_once()
		m_logger.exception.assert_called_once()
		m_logger.error.assert_called_once()

	def test_samba_raises(
		self, mocker: MockerFixture, f_user_mixin: LDAPUserMixin
	):
		m_logger = mocker.patch("core.views.mixins.ldap.user.logger")
		extended_operations: ExtendedOperationsRoot = (
			f_user_mixin.ldap_connection.extend
		)
		eo_microsoft: MicrosoftExtendedOperations = (
			extended_operations.microsoft
		)
		eo_microsoft.modify_password.side_effect = Exception

		f_user_mixin.ldap_connection.server.info.supported_extensions = []
		m_distinguished_name = "mock_dn"
		with pytest.raises(exc_user.UserUpdateError):
			f_user_mixin.ldap_set_password(
				user_dn=m_distinguished_name,
				user_pwd_new="new_pwd",
				set_by_admin=True,
			)
		eo_microsoft.modify_password.assert_called_once()
		m_logger.exception.assert_called_once()
		m_logger.error.assert_called_once()

	def test_adds_admin(self, f_user_mixin: LDAPUserMixin):
		extended_operations: ExtendedOperationsRoot = (
			f_user_mixin.ldap_connection.extend
		)
		eo_standard: StandardExtendedOperations = extended_operations.standard

		f_user_mixin.ldap_connection.server.info.supported_extensions = [
			"1.3.6.1.4.1.4203.1.11.1"
		]
		m_distinguished_name = "mock_dn"
		f_user_mixin.ldap_set_password(
			user_dn=m_distinguished_name,
			user_pwd_new="new_pwd",
			set_by_admin=True,
		)
		eo_standard.modify_password.assert_called_once_with(
			user=m_distinguished_name, new_password="new_pwd"
		)

	def test_samba_admin(self, f_user_mixin: LDAPUserMixin):
		extended_operations: ExtendedOperationsRoot = (
			f_user_mixin.ldap_connection.extend
		)
		eo_microsoft: MicrosoftExtendedOperations = (
			extended_operations.microsoft
		)

		f_user_mixin.ldap_connection.server.info.supported_extensions = []
		m_distinguished_name = "mock_dn"
		f_user_mixin.ldap_set_password(
			user_dn=m_distinguished_name,
			user_pwd_new="new_pwd",
			set_by_admin=True,
		)
		eo_microsoft.modify_password.assert_called_once_with(
			user=m_distinguished_name, new_password="new_pwd"
		)

	def test_adds_user(self, f_user_mixin: LDAPUserMixin):
		extended_operations: ExtendedOperationsRoot = (
			f_user_mixin.ldap_connection.extend
		)
		eo_standard: StandardExtendedOperations = extended_operations.standard

		f_user_mixin.ldap_connection.server.info.supported_extensions = [
			"1.3.6.1.4.1.4203.1.11.1"
		]
		m_distinguished_name = "mock_dn"
		f_user_mixin.ldap_set_password(
			user_dn=m_distinguished_name,
			user_pwd_new="new_pwd",
			user_pwd_old="old_pwd",
		)
		eo_standard.modify_password.assert_called_once_with(
			user=m_distinguished_name,
			new_password="new_pwd",
			old_password="old_pwd",
		)

	def test_samba_user(self, f_user_mixin: LDAPUserMixin):
		extended_operations: ExtendedOperationsRoot = (
			f_user_mixin.ldap_connection.extend
		)
		eo_microsoft: MicrosoftExtendedOperations = (
			extended_operations.microsoft
		)

		f_user_mixin.ldap_connection.server.info.supported_extensions = []
		m_distinguished_name = "mock_dn"
		f_user_mixin.ldap_set_password(
			user_dn=m_distinguished_name,
			user_pwd_new="new_pwd",
			user_pwd_old="old_pwd",
		)
		eo_microsoft.modify_password.assert_called_once_with(
			user=m_distinguished_name,
			new_password="new_pwd",
			old_password="old_pwd",
		)


class TestLdapUserExists:
	def test_raises_validation_error(self, f_user_mixin: LDAPUserMixin):
		with pytest.raises(ValidationError):
			f_user_mixin.ldap_user_exists()

	@pytest.mark.parametrize(
		"username, email",
		(
			(
				"testuser",
				f"testuser@{LDAP_DOMAIN}",
			),
			(
				None,
				f"testuser@{LDAP_DOMAIN}",
			),
			(
				"testuser",
				None,
			),
		),
	)
	def test_exists(
		self,
		username: str,
		email: str,
		f_user_mixin: LDAPUserMixin,
		fc_user_entry: LDAPUserEntryFactory,
	):
		f_user_mixin.ldap_connection.entries = [fc_user_entry()]

		# Should return exception
		with pytest.raises(exc_ldap.LDAPObjectExists):
			f_user_mixin.ldap_user_exists(username=username, email=email)

		# Should return True
		assert (
			f_user_mixin.ldap_user_exists(
				username=username, email=email, return_exception=False
			)
			is True
		)

	def test_returns_false(self, f_user_mixin: LDAPUserMixin, fc_user_entry):
		f_user_mixin.ldap_connection.entries = [
			fc_user_entry(username="someuser")
		]

		# Should return False
		assert (
			f_user_mixin.ldap_user_exists(
				username="testuser",
				email="testuser@{LDAP_DOMAIN}",
				return_exception=False,
			)
			is False
		)


class TestFetch:
	@pytest.mark.parametrize(
		"m_member_of_objects, user_account_control, sam_account_type, expected_account_type",
		(
			(
				# m_member_of_objects
				[
					{
						LOCAL_ATTR_NAME: "mock_group_2",
						LOCAL_ATTR_DN: "mock_group_2_dn",
					},
					{
						LOCAL_ATTR_NAME: "mock_group_3",
						LOCAL_ATTR_DN: "mock_group_3_dn",
					},
				],
				[LDAP_UF_NORMAL_ACCOUNT],  # user_account_control
				LDAPAccountTypes.SAM_NORMAL_USER_ACCOUNT.value,  # sam_account_type
				LDAPAccountTypes.SAM_USER_OBJECT.name,  # expected_account_type
			),
			(
				[],  # m_member_of_objects
				# user_account_control
				[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_ACCOUNT_DISABLE],
				LDAPAccountTypes.SAM_NORMAL_USER_ACCOUNT.value,  # sam_account_type
				LDAPAccountTypes.SAM_USER_OBJECT.name,  # expected_account_type
			),
		),
	)
	def test_success(
		self,
		mocker: MockerFixture,
		_fld,
		m_member_of_objects,
		user_account_control,
		sam_account_type,
		expected_account_type,
		f_user_mixin: LDAPUserMixin,
		fc_user_entry: LDAPUserEntryFactory,
		f_log_mixin: LogMixin,
		f_runtime_settings: RuntimeSettingsSingleton,
		f_ldap_object,
		f_default_user_filter,
	):
		## Groups
		_ldap_group_instances = [
			mocker.Mock(attributes=group_attrs)
			for group_attrs in m_member_of_objects
		]

		# Patch the class to return each mock in sequence
		mocker.patch(
			"core.views.mixins.ldap.user.LDAPGroup",
			side_effect=_ldap_group_instances,
		)
		m_primary_group = {
			LOCAL_ATTR_NAME: "mock_group_1",
			LOCAL_ATTR_RELATIVE_ID: 117,
			LOCAL_ATTR_DN: "mock_group_1_dn",
		}
		m_primary_group_id = m_primary_group[LOCAL_ATTR_RELATIVE_ID]
		m_group_mixin = mocker.patch(
			"core.views.mixins.ldap.user.GroupViewMixin"
		)
		m_group_mixin.get_group_by_rid.return_value = m_primary_group
		m_group_objects = [m_primary_group] + m_member_of_objects
		m_when_created = tz.make_aware(
			datetime.today()
		).strftime(DATE_FORMAT_ISO_8601_ALT)

		## UAC
		expected_enabled = not (LDAP_UF_ACCOUNT_DISABLE in user_account_control)
		m_user_entry: LDAPEntry = fc_user_entry(
			**{
				LDAP_ATTR_PRIMARY_GROUP_ID: m_primary_group_id,
				LDAP_ATTR_USER_GROUPS: [
					_g[LOCAL_ATTR_DN] for _g in m_member_of_objects
				],
				LDAP_ATTR_UAC: calc_permissions(user_account_control),
				LDAP_ATTR_ACCOUNT_TYPE: sam_account_type,
				LDAP_ATTR_CREATED: m_when_created,
			}
		)
		m_ldap_user = f_ldap_object(m_user_entry)
		m_ldap_user.is_enabled = expected_enabled
		mocker.patch(
			"core.views.mixins.ldap.user.LDAPUser",
			return_value=m_ldap_user,
		)

		# Execution
		result = f_user_mixin.ldap_user_fetch(user_search="testuser")
		assert f_user_mixin.search_filter == f_default_user_filter("testuser")

		# Assertions
		f_log_mixin.log.assert_called_once_with(
			user=1,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_USER,
			log_target=getldapattrvalue(
				m_user_entry,
				_fld(LOCAL_ATTR_USERNAME),
			),
		)
		assert isinstance(result, dict)
		assert result[LOCAL_ATTR_ACCOUNT_TYPE] == expected_account_type
		assert result[LOCAL_ATTR_PRIMARY_GROUP_ID] == m_primary_group_id
		for _g in m_group_objects:
			assert _g in result[LOCAL_ATTR_USER_GROUPS]
		assert result[LOCAL_ATTR_PERMISSIONS] == user_account_control
		assert result[LOCAL_ATTR_IS_ENABLED] == expected_enabled
		assert result[LOCAL_ATTR_CREATED] == m_when_created

	def test_raises_group_fetch_error(
		self,
		mocker: MockerFixture,
		f_user_mixin: LDAPUserMixin,
		fc_user_entry: LDAPUserEntryFactory,
		f_ldap_object,
	):
		m_user_entry: LDAPEntry = fc_user_entry(
			**{
				LDAP_ATTR_USER_GROUPS: [{"mock": "group"}],
			}
		)
		mocker.patch(
			"core.views.mixins.ldap.user.LDAPGroup", side_effect=Exception
		)
		mocker.patch(
			"core.views.mixins.ldap.user.LDAPUser",
			return_value=f_ldap_object(m_user_entry),
		)

		with pytest.raises(exc_user.UserGroupsFetchError):
			f_user_mixin.ldap_user_fetch(user_search="testuser")


class TestChangeStatus:
	@pytest.mark.parametrize(
		"enabled, permissions, expected_permissions, with_django_user",
		(
			# Enable enabled user
			(
				True,
				[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD],
				[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD],
				False,
			),
			# Disable enabled user
			(
				False,
				[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD],
				[
					LDAP_UF_NORMAL_ACCOUNT,
					LDAP_UF_DONT_EXPIRE_PASSWD,
					LDAP_UF_ACCOUNT_DISABLE,
				],
				False,
			),
			# Enable disabled user
			(
				True,
				[
					LDAP_UF_NORMAL_ACCOUNT,
					LDAP_UF_DONT_EXPIRE_PASSWD,
					LDAP_UF_ACCOUNT_DISABLE,
				],
				[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD],
				False,
			),
			# Disable disabled user
			(
				False,
				[
					LDAP_UF_NORMAL_ACCOUNT,
					LDAP_UF_DONT_EXPIRE_PASSWD,
					LDAP_UF_ACCOUNT_DISABLE,
				],
				[
					LDAP_UF_NORMAL_ACCOUNT,
					LDAP_UF_DONT_EXPIRE_PASSWD,
					LDAP_UF_ACCOUNT_DISABLE,
				],
				False,
			),
			# Enable enabled user with local django instance
			(
				True,
				[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD],
				[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD],
				True,
			),
			# Disable enabled user with local django instance
			(
				False,
				[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD],
				[
					LDAP_UF_NORMAL_ACCOUNT,
					LDAP_UF_DONT_EXPIRE_PASSWD,
					LDAP_UF_ACCOUNT_DISABLE,
				],
				True,
			),
			# Enable disabled user with local django instance
			(
				True,
				[
					LDAP_UF_NORMAL_ACCOUNT,
					LDAP_UF_DONT_EXPIRE_PASSWD,
					LDAP_UF_ACCOUNT_DISABLE,
				],
				[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD],
				True,
			),
			# Disable disabled user with local django instance
			(
				False,
				[
					LDAP_UF_NORMAL_ACCOUNT,
					LDAP_UF_DONT_EXPIRE_PASSWD,
					LDAP_UF_ACCOUNT_DISABLE,
				],
				[
					LDAP_UF_NORMAL_ACCOUNT,
					LDAP_UF_DONT_EXPIRE_PASSWD,
					LDAP_UF_ACCOUNT_DISABLE,
				],
				True,
			),
		),
		ids=[
			"Enable enabled user",
			"Disable enabled user",
			"Enable disabled user",
			"Disable disabled user",
			"Enable enabled user with local django instance",
			"Disable enabled user with local django instance",
			"Enable disabled user with local django instance",
			"Disable disabled user with local django instance",
		],
	)
	@pytest.mark.django_db
	def test_success(
		self,
		enabled: bool,
		permissions: list[str],
		expected_permissions: list[str],
		with_django_user: bool,
		mocker: MockerFixture,
		f_user_mixin: LDAPUserMixin,
		f_log_mixin: LogMixin,
		fc_user_entry: LDAPUserEntryFactory,
		f_runtime_settings: RuntimeSettingsSingleton,
		f_default_user_filter,
	):
		m_django_user: Union[User, MockType] = None
		if with_django_user:
			m_django_user = mocker.Mock()
			mocker.patch(
				"core.views.mixins.ldap.user.User.objects.get",
				return_value=m_django_user,
			)

		m_user_entry: LDAPEntry = fc_user_entry(
			**{LDAP_ATTR_UAC: calc_permissions(permissions)}
		)
		mocker.patch.object(
			f_user_mixin, "get_user_object", return_value=m_user_entry
		)
		f_user_mixin.ldap_user_change_status(
			username="testuser", enabled=enabled
		)
		f_user_mixin.ldap_connection.modify.assert_called_once_with(
			m_user_entry.entry_dn,
			{
				LDAP_ATTR_UAC: [
					(MODIFY_REPLACE, [calc_permissions(expected_permissions)])
				]
			},
		)
		f_log_mixin.log.assert_called_once_with(
			user=1,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target="testuser",
			message=LOG_EXTRA_ENABLE if enabled else LOG_EXTRA_DISABLE,
		)
		if m_django_user:
			assert m_django_user.is_enabled == enabled
			m_django_user.save.assert_called_once()

	def test_raises_anti_lockout(
		self,
		mocker: MockerFixture,
		fc_user_entry: LDAPUserEntryFactory,
		f_user_mixin: LDAPUserMixin,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		m_user_entry: LDAPEntry = fc_user_entry(
			**{LDAP_ATTR_UAC: calc_permissions([LDAP_UF_NORMAL_ACCOUNT])}
		)
		mocker.patch.object(
			f_user_mixin, "get_user_object", return_value=m_user_entry
		)
		f_runtime_settings.LDAP_AUTH_CONNECTION_USER_DN = m_user_entry.entry_dn
		with pytest.raises(exc_user.UserAntiLockout):
			f_user_mixin.ldap_user_change_status(
				username="testuser", enabled=False
			)

	def test_raises_permission_error(
		self,
		mocker: MockerFixture,
		fc_user_entry: LDAPUserEntryFactory,
		f_user_mixin: LDAPUserMixin,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		mocker.patch(
			"core.views.mixins.ldap.user.ldap_adsi.calc_permissions",
			side_effect=Exception,
		)
		m_user_entry: LDAPEntry = fc_user_entry(
			**{LDAP_ATTR_UAC: calc_permissions([LDAP_UF_NORMAL_ACCOUNT])}
		)
		mocker.patch.object(
			f_user_mixin, "get_user_object", return_value=m_user_entry
		)

		with pytest.raises(exc_user.UserPermissionError):
			f_user_mixin.ldap_user_change_status(
				username="testuser", enabled=False
			)


class TestUnlock:
	def test_success(
		self,
		mocker: MockerFixture,
		fc_user_entry: LDAPUserEntryFactory,
		f_user_mixin: LDAPUserMixin,
		f_log_mixin: LogMixin,
	):
		extended_operations: ExtendedOperationsRoot = (
			f_user_mixin.ldap_connection.extend
		)
		eo_microsoft: MicrosoftExtendedOperations = (
			extended_operations.microsoft
		)
		m_user_entry: LDAPEntry = fc_user_entry()
		mocker.patch.object(
			f_user_mixin, "get_user_object", return_value=m_user_entry
		)

		f_user_mixin.ldap_user_unlock(username="testuser")
		eo_microsoft.unlock_account.assert_called_once_with(
			user=m_user_entry.entry_dn
		)
		f_log_mixin.log.assert_called_once_with(
			user=1,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target="testuser",
			message=LOG_EXTRA_UNLOCK,
		)


class TestDelete:
	def test_success(
		self,
		mocker: MockerFixture,
		fc_user_entry: LDAPUserEntryFactory,
		f_user_mixin: LDAPUserMixin,
		f_log_mixin: LogMixin,
	):
		m_user_entry = fc_user_entry()
		mocker.patch.object(
			f_user_mixin, "get_user_object", return_value=m_user_entry
		)

		f_user_mixin.ldap_user_delete(username="testuser")
		f_user_mixin.ldap_connection.delete.assert_called_once_with(
			m_user_entry.entry_dn
		)
		f_log_mixin.log.assert_called_once_with(
			user=1,
			operation_type=LOG_ACTION_DELETE,
			log_target_class=LOG_CLASS_USER,
			log_target="testuser",
		)
