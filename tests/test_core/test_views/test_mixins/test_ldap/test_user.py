import pytest
from pytest_mock import MockType
from core.views.mixins.logs import LogMixin
from core.views.mixins.ldap.user import UserViewLDAPMixin
from core.ldap.defaults import LDAP_DOMAIN
from django.core.exceptions import ValidationError
from core.constants import user as ldap_user
from core.models.user import User, USER_TYPE_LDAP
from typing import Union
from ldap3 import MODIFY_DELETE, MODIFY_REPLACE
from core.views.mixins.utils import getldapattr
from core.models.choices.log import (
	LOG_ACTION_DELETE,
	LOG_ACTION_READ,
	LOG_ACTION_UPDATE,
	LOG_CLASS_USER,
	LOG_EXTRA_ENABLE,
	LOG_EXTRA_DISABLE,
	LOG_EXTRA_UNLOCK,
)
from core.ldap.types.account import LDAPAccountTypes
from core.ldap.adsi import (
	LDAP_FILTER_AND,
	LDAP_FILTER_OR,
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
from core.models.ldap_object import LDAPObject
from ldap3 import Entry as LDAPEntry
from ldap3.extend import (
	ExtendedOperationsRoot,
	StandardExtendedOperations,
	MicrosoftExtendedOperations,
)


@pytest.fixture
def f_user_mixin(mocker):
	mixin = UserViewLDAPMixin()
	mixin.ldap_connection = mocker.MagicMock()
	mixin.request = mocker.MagicMock()
	return mixin


@pytest.fixture(autouse=True)
def f_log_mixin(mocker):
	mock = mocker.patch("core.views.mixins.ldap.user.DBLogMixin", mocker.MagicMock())
	return mock


@pytest.fixture(autouse=True)
def f_runtime_settings(mocker, g_runtime_settings):
	mocker.patch("core.views.mixins.ldap.user.RuntimeSettings", g_runtime_settings)
	return g_runtime_settings


@pytest.fixture
def f_auth_field_username(f_runtime_settings: RuntimeSettingsSingleton):
	return f_runtime_settings.LDAP_AUTH_USER_FIELDS["username"]


@pytest.fixture
def f_auth_field_email(f_runtime_settings: RuntimeSettingsSingleton):
	return f_runtime_settings.LDAP_AUTH_USER_FIELDS["email"]


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
def f_default_user_filter():
	def maker(username):
		return f"(&(&(objectClass=person)(!(objectClass=computer)))(sAMAccountName={username}))"

	return maker


class FakeUserLDAPEntry(LDAPEntry):
	givenName: str = None
	sn: str = None
	initials: str = None


@pytest.fixture
def fc_user_entry(
	mocker, f_ldap_search_base, f_auth_field_email, f_auth_field_username, f_ldap_domain
):
	def maker(username="testuser", **kwargs):
		if "spec" in kwargs:
			mock: LDAPEntry = mocker.MagicMock(spec=kwargs.pop("spec"))
		else:
			mock: LDAPEntry = mocker.MagicMock()
		mock.entry_attributes = []
		mock.entry_attributes_as_dict = {}
		attrs = {
			f_auth_field_username: username,
			f_auth_field_email: f"{username}@{f_ldap_domain}",
			"distinguishedName": f"CN={username},CN=Users,{f_ldap_search_base}",
			ldap_user.FIRST_NAME: "Test",
			ldap_user.LAST_NAME: "User",
			ldap_user.INITIALS: "TU",
		} | kwargs
		for k, v in attrs.items():
			m_attr = mocker.Mock()
			m_attr.value = v
			m_attr.values = [v]
			setattr(mock, k, m_attr)
			mock.entry_attributes_as_dict[k] = [v]
			mock.entry_attributes.append(k)
		mock.entry_dn = attrs["distinguishedName"]
		return mock

	return maker


@pytest.fixture
def f_ldap_object(mocker):
	def maker(entry: LDAPEntry):
		m_ldap_object: Union[MockType, LDAPObject] = mocker.MagicMock()
		m_ldap_object.entry = entry
		m_ldap_object.attributes = {}
		for attr in entry.entry_attributes:
			m_ldap_object.attributes[attr] = getldapattr(entry, attr)
		return m_ldap_object

	return maker


@pytest.fixture
def f_group_dn(f_ldap_search_base):
	return f"CN=testgroup,OU=Groups,{f_ldap_search_base}"


class TestUserViewLDAPMixin:
	def test_get_user_object_filter_xor_raises(self, f_user_mixin: UserViewLDAPMixin):
		with pytest.raises(ValueError, match="single value"):
			f_user_mixin.get_user_object_filter(username="a", email="b")

	def test_get_user_object_filter_xor_match_raises(self, f_user_mixin: UserViewLDAPMixin):
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
				"(&(&(objectClass=person)(!(objectClass=computer)))(sAMAccountName=testuser))",
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
				f"(&(&(objectClass=person)(!(objectClass=computer)))(mail=testuser@{LDAP_DOMAIN}))",
			),
		),
	)
	def test_get_user_object_filter_xor(
		self,
		username: str,
		email: str,
		exclude_computers: bool,
		expected: str,
		f_user_mixin: UserViewLDAPMixin,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		f_runtime_settings.EXCLUDE_COMPUTER_ACCOUNTS = exclude_computers
		assert f_user_mixin.get_user_object_filter(username=username, email=email) == expected

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
				f"(&(&(objectClass=person)(!(objectClass=computer)))(|(sAMAccountName=testuser)(mail=testuser@{LDAP_DOMAIN})))",
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
				f"(&(&(objectClass=person)(!(objectClass=computer)))(&(sAMAccountName=testuser)(mail=testuser@{LDAP_DOMAIN})))",
			),
		),
	)
	def test_get_user_object_filter_no_xor(
		self,
		username: str,
		email: str,
		exclude_computers: bool,
		match_both: bool,
		expected: str,
		f_user_mixin: UserViewLDAPMixin,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		f_runtime_settings.EXCLUDE_COMPUTER_ACCOUNTS = exclude_computers
		assert (
			f_user_mixin.get_user_object_filter(
				username=username, email=email, xor=False, match_both=match_both
			)
			== expected
		)

	def test_get_user_entry_raises_value_error(self, f_user_mixin: UserViewLDAPMixin):
		with pytest.raises(ValueError):
			f_user_mixin.get_user_entry()

	def test_get_user_entry_raises_not_found(self, f_user_mixin: UserViewLDAPMixin):
		with pytest.raises(exc_user.UserEntryNotFound):
			f_user_mixin.get_user_entry(username="testuser", raise_if_not_exists=True)

	def test_get_user_entry_returns_none(self, f_user_mixin: UserViewLDAPMixin):
		assert f_user_mixin.get_user_entry(username="testuser") is None

	def test_get_user_entry_no_entries(self, f_user_mixin: UserViewLDAPMixin):
		f_user_mixin.ldap_connection.entries = []
		assert f_user_mixin.get_user_entry(username="some_user") is None

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
	def test_get_user_object(
		self,
		mocker,
		username,
		email,
		f_user_mixin: UserViewLDAPMixin,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		m_entry = mocker.Mock()
		setattr(m_entry, f_runtime_settings.LDAP_AUTH_USER_FIELDS["username"], username)
		setattr(m_entry, f_runtime_settings.LDAP_AUTH_USER_FIELDS["email"], email)
		f_user_mixin.ldap_connection.entries = [m_entry]

		m_get_user_entry = mocker.patch.object(f_user_mixin, "get_user_entry")
		f_user_mixin.get_user_object(username=username, email=email)
		f_user_mixin.ldap_connection.search.assert_called_once()
		m_get_user_entry.assert_called_once_with(username=username, email=email)

	def test_get_user_object_raises(self, f_user_mixin: UserViewLDAPMixin):
		with pytest.raises(ValidationError):
			f_user_mixin.get_user_object()

	def test_get_group_attributes(self, f_user_mixin: UserViewLDAPMixin, f_group_dn, mocker):
		m_group_attrs = ["some_attribute_list"]
		m_group = mocker.Mock()
		m_group.attributes = m_group_attrs
		m_ldap_object = mocker.patch("core.views.mixins.ldap.user.LDAPObject", return_value=m_group)

		result = f_user_mixin.get_group_attributes(group_dn=f_group_dn)
		m_ldap_object.assert_called_once_with(
			connection=f_user_mixin.ldap_connection,
			ldap_filter=f"({LDAP_FILTER_AND}(objectClass=group)(distinguishedName={f_group_dn}))",
			ldap_attrs=["objectSid"],
		)
		assert result == m_group_attrs

	def test_ldap_user_list(
		self,
		f_user_mixin: UserViewLDAPMixin,
		f_runtime_settings: RuntimeSettingsSingleton,
		fc_user_entry: dict,
		fc_user_permissions: int,
	):
		m_entries = [
			fc_user_entry("testuser1", **{"userAccountControl": fc_user_permissions()}),
			fc_user_entry(
				"testuser2",
				**{
					"userAccountControl": fc_user_permissions(
						[LDAP_UF_ACCOUNT_DISABLE, LDAP_UF_NORMAL_ACCOUNT]
					)
				},
			),
		]
		f_user_mixin.ldap_filter_object = (
			"(objectClass=" + f_runtime_settings.LDAP_AUTH_OBJECT_CLASS + ")"
		)
		f_user_mixin.ldap_filter_attr = f_user_mixin.filter_attr_builder(
			f_runtime_settings
		).get_list_attrs()
		f_user_mixin.ldap_connection.entries = m_entries
		result = f_user_mixin.ldap_user_list()
		assert isinstance(result, dict)
		for k in ["users", "headers"]:
			assert k in result

		for user in result["users"]:
			for k in ["userAccountControl", "displayName"]:
				assert k not in user

		assert result["users"][0]["is_enabled"] is True
		assert result["users"][1]["is_enabled"] is False

	@pytest.mark.parametrize(
		"m_user_data, expected_permissions",
		(
			(
				{
					"username": "testuser",
					"password": "some_password",
					"passwordConfirm": "some_password",
					ldap_user.FIRST_NAME: "Test",
					ldap_user.LAST_NAME: "User",
					"permission_list": [],
				},
				calc_permissions([LDAP_UF_NORMAL_ACCOUNT]),
			),
			(
				{
					"username": "testuser2",
					"password": "some_password",
					"passwordConfirm": "some_password",
					ldap_user.FIRST_NAME: "Test",
					ldap_user.LAST_NAME: "User 2",
					"permission_list": [
						LDAP_UF_ACCOUNT_DISABLE,
						LDAP_UF_NORMAL_ACCOUNT,
						LDAP_UF_DONT_EXPIRE_PASSWD,
					],
				},
				calc_permissions(
					[LDAP_UF_ACCOUNT_DISABLE, LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD]
				),
			),
			(
				{
					"username": "testuser3",
					"password": "some_password",
					"passwordConfirm": "some_password",
					"permission_list": [LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD],
				},
				calc_permissions([LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD]),
			),
			(
				{
					"username": "testuser4",
					"password": "some_password",
					"passwordConfirm": "some_password",
					"path": None,
				},
				calc_permissions([LDAP_UF_NORMAL_ACCOUNT]),
			),
		),
	)
	def test_ldap_user_insert_normal(
		self,
		m_user_data: dict,
		expected_permissions: int,
		f_ldap_search_base: str,
		f_user_mixin: UserViewLDAPMixin,
		f_runtime_settings: RuntimeSettingsSingleton,
		f_ldap_domain: str,
		f_auth_field_username,
	):
		m_user_rdn = f"CN=Users,{f_ldap_search_base}"
		m_user_name = m_user_data["username"]
		if not "path" in m_user_data:
			m_user_data["path"] = m_user_rdn
		expected_dn = f"CN={m_user_name},{m_user_rdn}"
		expected_attrs = {
			"userAccountControl": expected_permissions,
			f_auth_field_username: m_user_name,
			"objectClass": ["top", "person", "organizationalPerson", "user"],
			"userPrincipalName": f"{m_user_name}@{f_ldap_domain}",
		}
		for k in [ldap_user.FIRST_NAME, ldap_user.LAST_NAME]:
			if m_user_data.get(k, None):
				expected_attrs[k] = m_user_data[k]

		result = f_user_mixin.ldap_user_insert(user_data=m_user_data)
		f_user_mixin.ldap_connection.add.assert_called_with(
			expected_dn, f_runtime_settings.LDAP_AUTH_OBJECT_CLASS, attributes=expected_attrs
		)
		assert result == expected_dn

	@pytest.mark.parametrize(
		"m_user_data, key_mapping, expected_mapped",
		(
			(
				{
					"username": "testuser",
					"password": "some_password",
					"passwordConfirm": "some_password",
					"first_name": "Test",
					"last_name": "User",
				},
				{ldap_user.FIRST_NAME: "first_name", ldap_user.LAST_NAME: "last_name"},
				{
					ldap_user.FIRST_NAME: "Test",
					ldap_user.LAST_NAME: "User",
				},
			),
			(
				{
					"username": "testuser",
					"password": "some_password",
					"passwordConfirm": "some_password",
					"first_name": "Test",
					"l_name": "User",
				},
				{ldap_user.FIRST_NAME: "first_name", ldap_user.LAST_NAME: "last_name"},
				{
					ldap_user.FIRST_NAME: "Test",
					"l_name": "User",
				},
			),
		),
	)
	def test_ldap_user_insert_mapped(
		self,
		m_user_data: dict,
		key_mapping: dict,
		expected_mapped: dict,
		f_ldap_search_base: str,
		f_user_mixin: UserViewLDAPMixin,
		f_runtime_settings: RuntimeSettingsSingleton,
		f_ldap_domain: str,
		f_auth_field_username,
	):
		m_user_rdn = f"CN=Users,{f_ldap_search_base}"
		m_user_name = m_user_data["username"]
		m_user_data["path"] = m_user_rdn
		expected_dn = f"CN={m_user_name},{m_user_rdn}"
		expected_attrs = {
			**{
				"userAccountControl": calc_permissions([LDAP_UF_NORMAL_ACCOUNT]),
				f_auth_field_username: m_user_name,
				"objectClass": ["top", "person", "organizationalPerson", "user"],
				"userPrincipalName": f"{m_user_name}@{f_ldap_domain}",
			},
			**expected_mapped,
		}

		result = f_user_mixin.ldap_user_insert(user_data=m_user_data, key_mapping=key_mapping)
		f_user_mixin.ldap_connection.add.assert_called_with(
			expected_dn, f_runtime_settings.LDAP_AUTH_OBJECT_CLASS, attributes=expected_attrs
		)
		assert result == expected_dn

	def test_ldap_user_insert_raises_path_exc(self, mocker, f_user_mixin: UserViewLDAPMixin):
		mocker.patch("core.views.mixins.ldap.user.safe_dn", side_effect=Exception)
		with pytest.raises(exc_user.UserDNPathException):
			f_user_mixin.ldap_user_insert(user_data={})

	def test_ldap_user_insert_raises_add_exc(self, f_user_mixin: UserViewLDAPMixin):
		f_user_mixin.ldap_connection.add.side_effect = Exception
		with pytest.raises(exc_user.UserCreate):
			f_user_mixin.ldap_user_insert(
				user_data={
					"username": "testuser",
					"password": "some_password",
					"passwordConfirm": "some_password",
					"givenName": "Test",
					"sn": "User",
					"permission_list": [],
				}
			)

	def test_ldap_user_insert_returns_none(self, f_user_mixin: UserViewLDAPMixin):
		f_user_mixin.ldap_connection.add.side_effect = Exception
		assert (
			f_user_mixin.ldap_user_insert(
				user_data={
					"username": "testuser",
					"password": "some_password",
					"passwordConfirm": "some_password",
					"givenName": "Test",
					"sn": "User",
					"permission_list": [],
				},
				return_exception=False,
			)
			is None
		)

	@pytest.mark.parametrize(
		"user_dn, user_data, exc_match",
		(
			(False, None, "user_dn must be of type str"),
			("mock_dn", False, "user_data must be any of types"),
		),
	)
	def test_ldap_user_update_keys_raises_type_error(
		self,
		user_dn: str,
		user_data: str,
		exc_match: str,
		f_user_mixin: UserViewLDAPMixin,
	):
		with pytest.raises(TypeError, match=exc_match):
			f_user_mixin.ldap_user_update_keys(user_dn=user_dn, user_data=user_data)

	def test_ldap_user_update_keys_raises_value_error(self, f_user_mixin: UserViewLDAPMixin):
		with pytest.raises(ValueError, match="user_dn cannot be a falsy value"):
			f_user_mixin.ldap_user_update_keys(user_dn="", user_data={})

	def test_ldap_user_update_keys_dict(self, f_user_mixin: UserViewLDAPMixin, fc_user_entry):
		m_modify: MockType = f_user_mixin.ldap_connection.modify
		m_entry: LDAPEntry = fc_user_entry()
		m_user_dn = m_entry.entry_dn
		f_user_mixin.ldap_user_update_keys(
			user_dn=m_user_dn,
			user_data={
				ldap_user.FIRST_NAME: "new_name",
				ldap_user.COUNTRY: "",
			},
			replace_operation_keys=[ldap_user.FIRST_NAME],
			delete_operation_keys=[ldap_user.COUNTRY],
		)
		m_modify.assert_any_call(
			m_user_dn, {ldap_user.FIRST_NAME: [(MODIFY_REPLACE, ["new_name"])]}
		)
		m_modify.assert_any_call(m_user_dn, {ldap_user.COUNTRY: [(MODIFY_DELETE), []]})

	def test_ldap_user_update_keys_entry(
		self, mocker, f_user_mixin: UserViewLDAPMixin, fc_user_entry
	):
		mocker.patch("core.views.mixins.ldap.user.LDAPEntry", FakeUserLDAPEntry)
		m_modify: MockType = f_user_mixin.ldap_connection.modify
		m_entry: LDAPEntry = fc_user_entry(spec=FakeUserLDAPEntry)
		m_user_dn = m_entry.entry_dn
		f_user_mixin.ldap_user_update_keys(
			user_dn=m_user_dn,
			user_data=m_entry,
			replace_operation_keys=[ldap_user.FIRST_NAME],
			delete_operation_keys=[ldap_user.COUNTRY],
		)
		m_modify.assert_any_call(
			m_user_dn,
			{
				ldap_user.FIRST_NAME: [
					(MODIFY_REPLACE, [getldapattr(m_entry, ldap_user.FIRST_NAME)])
				]
			},
		)
		m_modify.assert_any_call(m_user_dn, {ldap_user.COUNTRY: [(MODIFY_DELETE), []]})

	def test_ldap_user_update_with_non_existing_keys(
		self, f_user_mixin: UserViewLDAPMixin, fc_user_entry
	):
		m_modify: MockType = f_user_mixin.ldap_connection.modify
		m_user_entry: LDAPEntry = fc_user_entry()
		m_user_dn = m_user_entry.entry_dn
		f_user_mixin.ldap_user_update_keys(
			user_dn=m_user_dn,
			user_data={
				ldap_user.FIRST_NAME: "new_name",
				ldap_user.COUNTRY: "",
			},
			replace_operation_keys=[ldap_user.FIRST_NAME, "some_key"],
			delete_operation_keys=[ldap_user.COUNTRY, "another_key"],
		)
		m_modify.assert_any_call(
			m_user_dn, {ldap_user.FIRST_NAME: [(MODIFY_REPLACE, ["new_name"])]}
		)
		m_modify.assert_any_call(
			m_user_dn,
			{
				ldap_user.COUNTRY: [(MODIFY_DELETE), []],
				"another_key": [(MODIFY_DELETE), []],
			},
		)

	@pytest.mark.parametrize(
		"username, user_data, permission_list, exc_match",
		(
			(None, None, None, "username must be of type str"),
			("username", None, None, "user_data must be of type dict"),
			("username", {}, {"k": "not_a_list"}, "permission_list must be of type list"),
		),
	)
	def test_ldap_user_update_raises_type_error(
		self,
		username,
		user_data,
		permission_list,
		exc_match,
		f_user_mixin: UserViewLDAPMixin,
	):
		with pytest.raises(TypeError, match=exc_match):
			f_user_mixin.ldap_user_update(
				username=username, user_data=user_data, permission_list=permission_list
			)

	@pytest.mark.django_db
	@pytest.mark.parametrize(
		"user_data, permission_list",
		[
			({ldap_user.EMAIL: f"newemail@{LDAP_DOMAIN}"}, None),  # Auth Field Update
			({ldap_user.FIRST_NAME: "new_name"}, None),  # Simple attribute update
			({ldap_user.FIRST_NAME: "new_name"}, [LDAP_UF_NORMAL_ACCOUNT]),  # With permissions
			({ldap_user.COUNTRY: "United States"}, None),  # Country code update
			(
				{"groupsToAdd": ["CN=Group1"], "groupsToRemove": ["CN=Group2"]},
				None,
			),  # Group updates
			({"someAttribute": ""}, None),  # Attribute deletion
		],
	)
	def test_ldap_user_update_success(
		self,
		mocker,
		f_user_mixin: UserViewLDAPMixin,
		fc_user_entry: LDAPEntry,
		user_data: dict,
		permission_list: list,
		f_runtime_settings: RuntimeSettingsSingleton,
		f_log_mixin: LogMixin,
	):
		"""Test successful user updates"""
		# Setup
		m_user_id = 1
		f_user_mixin.request.user.id = m_user_id
		m_update_keys: MockType = mocker.patch.object(f_user_mixin, "ldap_user_update_keys")

		m_entry: LDAPEntry = fc_user_entry()
		mocker.patch.object(f_user_mixin, "get_user_object", return_value=m_entry)

		m_django_user: Union[MockType, User] = mocker.MagicMock()
		m_user_cls: MockType = mocker.patch("core.views.mixins.ldap.user.User", mocker.MagicMock())
		m_user_cls.objects.get.return_value = m_django_user

		# Test
		username = getldapattr(m_entry, f_runtime_settings.LDAP_AUTH_USER_FIELDS["username"])
		result = f_user_mixin.ldap_user_update(username, user_data, permission_list)

		# Verify
		assert result == f_user_mixin.ldap_connection
		m_update_keys.assert_called_once()
		f_log_mixin.log.assert_called_once_with(
			user=m_user_id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=username,
		)
		m_user_cls.objects.get.assert_called_once()
		m_django_user.email = user_data.get(f_runtime_settings.LDAP_AUTH_USER_FIELDS["email"], None)
		m_django_user.save.assert_called_once()

	def test_ldap_user_update_permission_error(
		self,
		mocker,
		f_user_mixin: UserViewLDAPMixin,
		fc_user_entry,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		"""Test permission calculation error"""
		m_entry: LDAPEntry = fc_user_entry()
		mocker.patch.object(f_user_mixin, "get_user_object", return_value=m_entry)
		mocker.patch("core.ldap.adsi.calc_permissions", side_effect=Exception)

		username = getldapattr(m_entry, f_runtime_settings.LDAP_AUTH_USER_FIELDS["username"])
		with pytest.raises(exc_user.UserPermissionError):
			f_user_mixin.ldap_user_update(
				username, {ldap_user.FIRST_NAME: "new_name"}, ["invalid_permission"]
			)

	def test_ldap_user_update_country_error(
		self,
		mocker,
		f_user_mixin: UserViewLDAPMixin,
		fc_user_entry,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		"""Test invalid country code handling"""
		m_entry: LDAPEntry = fc_user_entry()
		mocker.patch.object(f_user_mixin, "get_user_object", return_value=m_entry)

		username = getldapattr(m_entry, f_runtime_settings.LDAP_AUTH_USER_FIELDS["username"])
		with pytest.raises(exc_user.UserCountryUpdateError):
			f_user_mixin.ldap_user_update(
				username,
				{ldap_user.COUNTRY: "invalid_country"},
				None,
			)

	def test_ldap_user_update_group_conflict(
		self,
		mocker,
		f_user_mixin: UserViewLDAPMixin,
		fc_user_entry,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		"""Test conflicting group operations"""
		m_entry: LDAPEntry = fc_user_entry()
		mocker.patch.object(f_user_mixin, "get_user_object", return_value=m_entry)

		username = getldapattr(m_entry, f_runtime_settings.LDAP_AUTH_USER_FIELDS["username"])
		with pytest.raises(exc_user.BadGroupSelection):
			f_user_mixin.ldap_user_update(
				username,
				{
					"groupsToAdd": ["CN=Group1"],
					"groupsToRemove": ["CN=Group1"],  # Same group
				},
				None,
			)

	def test_ldap_user_update_attribute_error(
		self,
		mocker,
		f_user_mixin: UserViewLDAPMixin,
		fc_user_entry,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		"""Test attribute update failure"""
		m_entry: LDAPEntry = fc_user_entry()
		mocker.patch.object(f_user_mixin, "get_user_object", return_value=m_entry)
		f_user_mixin.ldap_connection.modify.side_effect = Exception("Update failed")

		username = getldapattr(m_entry, f_runtime_settings.LDAP_AUTH_USER_FIELDS["username"])
		with pytest.raises(exc_user.UserUpdateError):
			f_user_mixin.ldap_user_update(username, {ldap_user.FIRST_NAME: "new_name"}, None)

	def test_ldap_user_update_lockout(
		self, mocker, f_user_mixin: UserViewLDAPMixin, fc_user_entry, f_runtime_settings
	):
		"""Test lockout time setting"""
		m_entry: LDAPEntry = fc_user_entry()
		mocker.patch.object(f_user_mixin, "get_user_object", return_value=m_entry)
		mocker.patch.object(f_user_mixin, "ldap_user_update_keys", return_value=None)
		m_data = {ldap_user.FIRST_NAME: "new_name"}
		username = m_entry.entry_attributes_as_dict[
			f_runtime_settings.LDAP_AUTH_USER_FIELDS["username"]
		][0]
		f_user_mixin.ldap_user_update(username, m_data, [LDAP_UF_LOCKOUT])
		f_user_mixin.ldap_user_update_keys.assert_called_once_with(
			user_dn=m_entry.entry_attributes_as_dict["distinguishedName"][0],
			user_data=m_data
			| {
				"lockoutTime": 30,
				ldap_user.USER_ACCOUNT_CONTROL: calc_permissions([LDAP_UF_LOCKOUT]),
			},
			replace_operation_keys=[
				ldap_user.FIRST_NAME,
				"lockoutTime",
				ldap_user.USER_ACCOUNT_CONTROL,
			],
			delete_operation_keys=[],
		)

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
	def test_ldap_set_password_raises_type_error(
		self,
		f_user_mixin: UserViewLDAPMixin,
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

	def test_ldap_set_password_raises_value_error(self, f_user_mixin: UserViewLDAPMixin):
		with pytest.raises(ValueError):
			f_user_mixin.ldap_set_password(user_dn="mock_dn", user_pwd_new="", set_by_admin=True)

	def test_ldap_set_password_raises_pwds_dont_match(self, f_user_mixin: UserViewLDAPMixin):
		with pytest.raises(exc_user.UserOldPasswordRequired):
			f_user_mixin.ldap_set_password(
				user_dn="mock_dn",
				user_pwd_new="new_pwd",
				user_pwd_old="",
			)

	def test_ldap_set_password_adds_raises(self, mocker, f_user_mixin: UserViewLDAPMixin):
		m_logger = mocker.patch("core.views.mixins.ldap.user.logger")
		extended_operations: ExtendedOperationsRoot = f_user_mixin.ldap_connection.extend
		eo_standard: StandardExtendedOperations = extended_operations.standard
		eo_standard.modify_password.side_effect = Exception

		f_user_mixin.ldap_connection.server.info.supported_extensions = ["1.3.6.1.4.1.4203.1.11.1"]
		m_distinguished_name = "mock_dn"
		with pytest.raises(exc_user.UserUpdateError):
			f_user_mixin.ldap_set_password(
				user_dn=m_distinguished_name, user_pwd_new="new_pwd", set_by_admin=True
			)
		eo_standard.modify_password.assert_called_once()
		m_logger.exception.assert_called_once()
		m_logger.error.assert_called_once()

	def test_ldap_set_password_samba_raises(self, mocker, f_user_mixin: UserViewLDAPMixin):
		m_logger = mocker.patch("core.views.mixins.ldap.user.logger")
		extended_operations: ExtendedOperationsRoot = f_user_mixin.ldap_connection.extend
		eo_microsoft: MicrosoftExtendedOperations = extended_operations.microsoft
		eo_microsoft.modify_password.side_effect = Exception

		f_user_mixin.ldap_connection.server.info.supported_extensions = []
		m_distinguished_name = "mock_dn"
		with pytest.raises(exc_user.UserUpdateError):
			f_user_mixin.ldap_set_password(
				user_dn=m_distinguished_name, user_pwd_new="new_pwd", set_by_admin=True
			)
		eo_microsoft.modify_password.assert_called_once()
		m_logger.exception.assert_called_once()
		m_logger.error.assert_called_once()

	def test_ldap_set_password_adds_admin(self, f_user_mixin: UserViewLDAPMixin):
		extended_operations: ExtendedOperationsRoot = f_user_mixin.ldap_connection.extend
		eo_standard: StandardExtendedOperations = extended_operations.standard

		f_user_mixin.ldap_connection.server.info.supported_extensions = ["1.3.6.1.4.1.4203.1.11.1"]
		m_distinguished_name = "mock_dn"
		f_user_mixin.ldap_set_password(
			user_dn=m_distinguished_name, user_pwd_new="new_pwd", set_by_admin=True
		)
		eo_standard.modify_password.assert_called_once_with(
			user=m_distinguished_name, new_password="new_pwd"
		)

	def test_ldap_set_password_samba_admin(self, f_user_mixin: UserViewLDAPMixin):
		extended_operations: ExtendedOperationsRoot = f_user_mixin.ldap_connection.extend
		eo_microsoft: MicrosoftExtendedOperations = extended_operations.microsoft

		f_user_mixin.ldap_connection.server.info.supported_extensions = []
		m_distinguished_name = "mock_dn"
		f_user_mixin.ldap_set_password(
			user_dn=m_distinguished_name, user_pwd_new="new_pwd", set_by_admin=True
		)
		eo_microsoft.modify_password.assert_called_once_with(
			user=m_distinguished_name, new_password="new_pwd"
		)

	def test_ldap_set_password_adds_user(self, f_user_mixin: UserViewLDAPMixin):
		extended_operations: ExtendedOperationsRoot = f_user_mixin.ldap_connection.extend
		eo_standard: StandardExtendedOperations = extended_operations.standard

		f_user_mixin.ldap_connection.server.info.supported_extensions = ["1.3.6.1.4.1.4203.1.11.1"]
		m_distinguished_name = "mock_dn"
		f_user_mixin.ldap_set_password(
			user_dn=m_distinguished_name, user_pwd_new="new_pwd", user_pwd_old="old_pwd"
		)
		eo_standard.modify_password.assert_called_once_with(
			user=m_distinguished_name,
			new_password="new_pwd",
			old_password="old_pwd",
		)

	def test_ldap_set_password_samba_user(self, f_user_mixin: UserViewLDAPMixin):
		extended_operations: ExtendedOperationsRoot = f_user_mixin.ldap_connection.extend
		eo_microsoft: MicrosoftExtendedOperations = extended_operations.microsoft

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

	def test_ldap_user_exists_raises_validation_error(self, f_user_mixin: UserViewLDAPMixin):
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
	def test_ldap_user_exists(
		self, username: str, email: str, f_user_mixin: UserViewLDAPMixin, fc_user_entry
	):
		f_user_mixin.ldap_connection.entries = [fc_user_entry()]

		# Should return exception
		with pytest.raises(exc_ldap.LDAPObjectExists):
			f_user_mixin.ldap_user_exists(username=username, email=email)

		# Should return True
		assert (
			f_user_mixin.ldap_user_exists(username=username, email=email, return_exception=False)
			is True
		)

	def test_ldap_user_exists_returns_false(self, f_user_mixin: UserViewLDAPMixin, fc_user_entry):
		f_user_mixin.ldap_connection.entries = [fc_user_entry(username="someuser")]

		# Should return False
		assert (
			f_user_mixin.ldap_user_exists(
				username="testuser", email="testuser@{LDAP_DOMAIN}", return_exception=False
			)
			is False
		)

	@pytest.mark.parametrize(
		"m_member_of_objects, user_account_control, sam_account_type, expected_account_type",
		(
			(
				# m_member_of_objects
				[{"cn": "mock_group_2", "distinguishedName": "mock_group_2_dn"}],
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
	def test_ldap_user_fetch(
		self,
		mocker,
		m_member_of_objects,
		user_account_control,
		sam_account_type,
		expected_account_type,
		f_user_mixin: UserViewLDAPMixin,
		fc_user_entry,
		f_log_mixin: LogMixin,
		f_runtime_settings: RuntimeSettingsSingleton,
		f_ldap_object,
		f_default_user_filter,
	):
		# Setup
		f_user_mixin.request.user.id = 1

		## Groups
		m_primary_group = {
			"cn": "mock_group_1",
			"objectRid": 117,
			"distinguishedName": "mock_group_1_dn",
		}
		m_primary_group_id = m_primary_group["objectRid"]
		m_group_mixin = mocker.patch("core.views.mixins.ldap.user.GroupViewMixin")
		m_group_mixin.get_group_by_rid.return_value = m_primary_group
		m_group_objects = [m_primary_group] + m_member_of_objects

		## UAC
		expected_enabled = not (LDAP_UF_ACCOUNT_DISABLE in user_account_control)
		m_user_entry: LDAPEntry = fc_user_entry(
			**{
				"primaryGroupID": m_primary_group_id,
				"memberOf": [_g["distinguishedName"] for _g in m_member_of_objects],
				"userAccountControl": calc_permissions(user_account_control),
				"sAMAccountType": sam_account_type,
			}
		)
		m_get_group_attributes: MockType = mocker.patch.object(
			f_user_mixin, "get_group_attributes", side_effect=m_member_of_objects
		)
		mocker.patch(
			"core.views.mixins.ldap.user.LDAPObject", return_value=f_ldap_object(m_user_entry)
		)

		# Execution
		result = f_user_mixin.ldap_user_fetch(user_search="testuser")
		assert f_user_mixin.ldap_filter_object == f_default_user_filter("testuser")

		# Assertions
		f_log_mixin.log.assert_called_once_with(
			user=1,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_USER,
			log_target=getldapattr(
				m_user_entry, f_runtime_settings.LDAP_AUTH_USER_FIELDS["username"]
			),
		)
		m_get_group_attributes.call_count == 2
		assert isinstance(result, dict)
		assert result["sAMAccountType"] == expected_account_type
		assert result["primaryGroupID"] == m_primary_group_id
		for _g in m_group_objects:
			assert _g in result["memberOfObjects"]
		assert result["permission_list"] == user_account_control
		assert result["is_enabled"] == expected_enabled

	def test_ldap_user_fetch_raises_group_fetch_error(
		self,
		mocker,
		f_user_mixin: UserViewLDAPMixin,
		fc_user_entry,
		f_ldap_object,
	):
		m_user_entry: LDAPEntry = fc_user_entry(
			**{
				"memberOf": [{"mock": "group"}],
			}
		)
		mocker.patch.object(f_user_mixin, "get_group_attributes", side_effect=Exception)
		mocker.patch(
			"core.views.mixins.ldap.user.LDAPObject", return_value=f_ldap_object(m_user_entry)
		)

		with pytest.raises(exc_user.UserGroupsFetchError):
			f_user_mixin.ldap_user_fetch(user_search="testuser")

	@pytest.mark.parametrize(
		"mocked_exc_effect, expected_log_count",
		(
			(Exception, 1),
			([True, Exception], 1),
			([Exception, Exception], 2),
		),
	)
	def test_ldap_user_fetch_logs_permission_errors(
		self,
		mocked_exc_effect,
		expected_log_count,
		mocker,
		f_user_mixin: UserViewLDAPMixin,
		fc_user_entry,
		f_ldap_object,
	):
		m_logger = mocker.patch("core.views.mixins.ldap.user.logger")
		m_primary_group = {"cn": "mock_primary_group", "objectRid": 117}
		m_primary_group_id = m_primary_group["objectRid"]
		m_group_mixin = mocker.patch("core.views.mixins.ldap.user.GroupViewMixin")
		m_group_mixin.get_group_by_rid.return_value = m_primary_group
		m_member_of_objects = [{"distinguishedName": "mock_group_dn"}]
		m_user_entry: LDAPEntry = fc_user_entry(
			**{
				"primaryGroupID": m_primary_group_id,
				"memberOf": [_g["distinguishedName"] for _g in m_member_of_objects],
				"sAMAccountType": LDAPAccountTypes.SAM_NORMAL_USER_ACCOUNT.value,
			}
		)
		mocker.patch.object(f_user_mixin, "get_group_attributes", side_effect=m_member_of_objects)
		mocker.patch(
			"core.views.mixins.ldap.user.ldap_adsi.list_user_perms", side_effect=mocked_exc_effect
		)
		mocker.patch(
			"core.views.mixins.ldap.user.LDAPObject", return_value=f_ldap_object(m_user_entry)
		)

		f_user_mixin.ldap_user_fetch(user_search="testuser")
		m_logger.error.call_count == expected_log_count
		m_logger.exception.call_count == expected_log_count

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
				[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD, LDAP_UF_ACCOUNT_DISABLE],
				False,
			),
			# Enable disabled user
			(
				True,
				[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD, LDAP_UF_ACCOUNT_DISABLE],
				[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD],
				False,
			),
			# Disable disabled user
			(
				False,
				[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD, LDAP_UF_ACCOUNT_DISABLE],
				[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD, LDAP_UF_ACCOUNT_DISABLE],
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
				[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD, LDAP_UF_ACCOUNT_DISABLE],
				True,
			),
			# Enable disabled user with local django instance
			(
				True,
				[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD, LDAP_UF_ACCOUNT_DISABLE],
				[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD],
				True,
			),
			# Disable disabled user with local django instance
			(
				False,
				[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD, LDAP_UF_ACCOUNT_DISABLE],
				[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD, LDAP_UF_ACCOUNT_DISABLE],
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
	def test_ldap_user_change_status(
		self,
		enabled: bool,
		permissions: list[str],
		expected_permissions: list[str],
		with_django_user: bool,
		mocker,
		f_user_mixin: UserViewLDAPMixin,
		f_log_mixin: LogMixin,
		fc_user_entry,
		f_runtime_settings: RuntimeSettingsSingleton,
		f_default_user_filter,
	):
		f_user_mixin.request.user.id = 1
		m_django_user: Union[User, MockType] = None
		if with_django_user:
			m_django_user = mocker.Mock()
			mocker.patch("core.views.mixins.ldap.user.User.objects.get", return_value=m_django_user)

		m_user_entry: LDAPEntry = fc_user_entry(
			**{"userAccountControl": calc_permissions(permissions)}
		)
		mocker.patch.object(f_user_mixin, "get_user_object", return_value=m_user_entry)
		f_user_mixin.ldap_user_change_status(username="testuser", enabled=enabled)
		f_user_mixin.ldap_connection.modify.assert_called_once_with(
			m_user_entry.entry_dn,
			{"userAccountControl": [(MODIFY_REPLACE, [calc_permissions(expected_permissions)])]},
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

	def test_ldap_user_change_status_raises_anti_lockout(
		self,
		mocker,
		fc_user_entry,
		f_user_mixin: UserViewLDAPMixin,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		m_user_entry: LDAPEntry = fc_user_entry(
			**{"userAccountControl": calc_permissions([LDAP_UF_NORMAL_ACCOUNT])}
		)
		mocker.patch.object(f_user_mixin, "get_user_object", return_value=m_user_entry)
		f_runtime_settings.LDAP_AUTH_CONNECTION_USER_DN = m_user_entry.entry_dn
		with pytest.raises(exc_user.UserAntiLockout):
			f_user_mixin.ldap_user_change_status(username="testuser", enabled=False)

	def test_ldap_user_change_status_raises_permission_error(
		self,
		mocker,
		fc_user_entry,
		f_user_mixin: UserViewLDAPMixin,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		mocker.patch(
			"core.views.mixins.ldap.user.ldap_adsi.calc_permissions", side_effect=Exception
		)
		m_user_entry: LDAPEntry = fc_user_entry(
			**{"userAccountControl": calc_permissions([LDAP_UF_NORMAL_ACCOUNT])}
		)
		mocker.patch.object(f_user_mixin, "get_user_object", return_value=m_user_entry)

		with pytest.raises(exc_user.UserPermissionError):
			f_user_mixin.ldap_user_change_status(username="testuser", enabled=False)

	def test_ldap_user_unlock(
		self,
		mocker,
		fc_user_entry,
		f_user_mixin: UserViewLDAPMixin,
		f_log_mixin: LogMixin,
	):
		f_user_mixin.request.user.id = 1
		extended_operations: ExtendedOperationsRoot = f_user_mixin.ldap_connection.extend
		eo_microsoft: MicrosoftExtendedOperations = extended_operations.microsoft
		m_user_entry: LDAPEntry = fc_user_entry()
		mocker.patch.object(f_user_mixin, "get_user_object", return_value=m_user_entry)

		f_user_mixin.ldap_user_unlock(username="testuser")
		eo_microsoft.unlock_account.assert_called_once_with(user=m_user_entry.entry_dn)
		f_log_mixin.log.assert_called_once_with(
			user=1,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target="testuser",
			message=LOG_EXTRA_UNLOCK,
		)

	def test_ldap_user_delete(
		self,
		mocker,
		fc_user_entry,
		f_user_mixin: UserViewLDAPMixin,
		f_log_mixin: LogMixin,
	):
		f_user_mixin.request.user.id = 1
		m_user_entry: LDAPEntry = fc_user_entry()
		mocker.patch.object(f_user_mixin, "get_user_object", return_value=m_user_entry)

		f_user_mixin.ldap_user_delete(username="testuser")
		f_user_mixin.ldap_connection.delete.assert_called_once_with(m_user_entry.entry_dn)
		f_log_mixin.log.assert_called_once_with(
			user=1,
			operation_type=LOG_ACTION_DELETE,
			log_target_class=LOG_CLASS_USER,
			log_target="testuser",
		)
