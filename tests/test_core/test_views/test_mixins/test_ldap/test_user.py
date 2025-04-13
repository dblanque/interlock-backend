import pytest
from pytest_mock import MockType
from core.views.mixins.logs import LogMixin
from core.views.mixins.ldap.user import UserViewLDAPMixin
from core.ldap.defaults import LDAP_DOMAIN
from django.core.exceptions import ValidationError
from core.constants import user as ldap_user
from core.models.user import User
from typing import Union
from ldap3 import MODIFY_DELETE, MODIFY_REPLACE
from core.models.choices.log import LOG_ACTION_UPDATE, LOG_CLASS_USER
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
from core.exceptions import users as exc_user
from ldap3 import Entry as LDAPEntry

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


@pytest.fixture
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
def fc_user_entry(
	mocker, f_ldap_search_base, f_auth_field_email, f_auth_field_username, f_ldap_domain
):
	def maker(username="testuser", **kwargs):
		mock = mocker.MagicMock()
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
			setattr(mock, k, m_attr)
			mock.entry_attributes_as_dict[k] = [v]
		mock.entry_dn = attrs["distinguishedName"]
		return mock

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

	def test_get_user_entry_no_entries(self, f_user_mixin: UserViewLDAPMixin):
		f_user_mixin.ldap_connection.entries = []
		assert f_user_mixin.get_user_entry(username="some_user") is None

	@pytest.mark.parametrize(
		"test_kwargs",
		(
			{"username": "testuser"},
			{
				"email": f"testuser@{LDAP_DOMAIN}",
			},
			{
				"username": "testuser",
				"email": f"testuser@{LDAP_DOMAIN}",
			},
		),
	)
	def test_get_user_object(
		self,
		mocker,
		test_kwargs,
		f_user_mixin: UserViewLDAPMixin,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		m_entry = mocker.Mock()
		setattr(m_entry, f_runtime_settings.LDAP_AUTH_USER_FIELDS["username"], "testuser")
		setattr(
			m_entry, f_runtime_settings.LDAP_AUTH_USER_FIELDS["email"], f"testuser@{LDAP_DOMAIN}"
		)
		f_user_mixin.ldap_connection.entries = [m_entry]
		result = f_user_mixin.get_user_object(**test_kwargs)
		f_user_mixin.ldap_connection.search.assert_called_once()
		assert result == m_entry

	def test_get_user_object_raises(self, f_user_mixin: UserViewLDAPMixin):
		with pytest.raises(ValidationError):
			f_user_mixin.get_user_object()

	def test_get_group_attributes(self, f_user_mixin: UserViewLDAPMixin, f_group_dn, mocker):
		m_group_attrs = ["some_attribute_list"]
		m_group = mocker.Mock()
		m_group.attributes = m_group_attrs
		m_ldap_object = mocker.patch("core.views.mixins.ldap.user.LDAPObject", return_value=m_group)

		result = f_user_mixin.get_group_attributes(groupDn=f_group_dn)
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


	def test_ldap_user_update_keys(self, f_user_mixin: UserViewLDAPMixin, fc_user_entry):
		m_modify: MockType = f_user_mixin.ldap_connection.modify
		m_user_entry = fc_user_entry()
		m_user_dn = m_user_entry.distinguishedName.value[0]
		f_user_mixin.ldap_user_update_keys(
			user_dn=m_user_dn,
			user_data={
				ldap_user.FIRST_NAME: "new_name",
				ldap_user.COUNTRY: "",
			},
			replace_operation_keys=[ldap_user.FIRST_NAME],
			delete_operation_keys=[ldap_user.COUNTRY],
		)
		m_modify.assert_any_call(m_user_dn, {
			ldap_user.FIRST_NAME: [(MODIFY_REPLACE, ["new_name"])]
		})
		m_modify.assert_any_call(m_user_dn, {
			ldap_user.COUNTRY: [(MODIFY_DELETE), []]
		})


	def test_ldap_user_update_with_non_existing_keys(self, f_user_mixin: UserViewLDAPMixin, fc_user_entry):
		m_modify: MockType = f_user_mixin.ldap_connection.modify
		m_user_entry = fc_user_entry()
		m_user_dn = m_user_entry.distinguishedName.value[0]
		f_user_mixin.ldap_user_update_keys(
			user_dn=m_user_dn,
			user_data={
				ldap_user.FIRST_NAME: "new_name",
				ldap_user.COUNTRY: "",
			},
			replace_operation_keys=[ldap_user.FIRST_NAME, "some_key"],
			delete_operation_keys=[ldap_user.COUNTRY, "another_key"],
		)
		m_modify.assert_any_call(m_user_dn, {
			ldap_user.FIRST_NAME: [(MODIFY_REPLACE, ["new_name"])]
		})
		m_modify.assert_any_call(m_user_dn, {
			ldap_user.COUNTRY: [(MODIFY_DELETE), []],
			"another_key": [(MODIFY_DELETE), []],
		})


	@pytest.mark.parametrize(
		"username, user_data, permission_list, exc_match",
		(
			(None, None, None, "username must be of type str"),
			("username", None, None, "user_data must be of type dict"),
			("username", {}, {"k":"not_a_list"}, "permission_list must be of type list"),
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
		m_update_keys: MockType = mocker.patch.object(
			f_user_mixin, "ldap_user_update_keys")

		m_entry = fc_user_entry()
		mocker.patch.object(f_user_mixin, "get_user_entry", return_value=m_entry)

		m_django_user: Union[MockType, User] = mocker.MagicMock()
		m_user_cls: MockType = mocker.patch(
			"core.views.mixins.ldap.user.User", mocker.MagicMock())
		m_user_cls.objects.get.return_value = m_django_user

		# Test
		username = getattr(m_entry, f_runtime_settings.LDAP_AUTH_USER_FIELDS["username"]).value[0]
		result = f_user_mixin.ldap_user_update(username, user_data, permission_list)

		# Verify
		assert result == f_user_mixin.ldap_connection
		m_update_keys.assert_called_once()
		f_log_mixin.log.assert_called_once_with(
			user=m_user_id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			log_target=username
		)
		m_user_cls.objects.get.assert_called_once()
		m_django_user.email = user_data.get(f_runtime_settings.LDAP_AUTH_USER_FIELDS["email"], None)
		m_django_user.save.assert_called_once()

	def test_ldap_user_update_permission_error(self, mocker, f_user_mixin: UserViewLDAPMixin, fc_user_entry, f_runtime_settings):
		"""Test permission calculation error"""
		mock_entry = fc_user_entry()
		mocker.patch.object(f_user_mixin, "get_user_entry", return_value=mock_entry)
		mocker.patch("core.ldap.adsi.calc_permissions", side_effect=Exception)

		username = getattr(mock_entry, f_runtime_settings.LDAP_AUTH_USER_FIELDS["username"]).value[0]
		with pytest.raises(exc_user.UserPermissionError):
			f_user_mixin.ldap_user_update(
				username, {ldap_user.FIRST_NAME: "new_name"}, ["invalid_permission"]
			)

	def test_ldap_user_update_country_error(self, mocker, f_user_mixin: UserViewLDAPMixin, fc_user_entry, f_runtime_settings):
		"""Test invalid country code handling"""
		mock_entry = fc_user_entry()
		mocker.patch.object(f_user_mixin, "get_user_entry", return_value=mock_entry)

		username = getattr(mock_entry, f_runtime_settings.LDAP_AUTH_USER_FIELDS["username"]).value[0]
		with pytest.raises(exc_user.UserCountryUpdateError):
			f_user_mixin.ldap_user_update(
				username,
				{ldap_user.COUNTRY: "invalid_country"},
				None,
			)

	def test_ldap_user_update_group_conflict(self, mocker, f_user_mixin: UserViewLDAPMixin, fc_user_entry, f_runtime_settings):
		"""Test conflicting group operations"""
		mock_entry = fc_user_entry()
		mocker.patch.object(f_user_mixin, "get_user_entry", return_value=mock_entry)

		username = getattr(mock_entry, f_runtime_settings.LDAP_AUTH_USER_FIELDS["username"]).value[0]
		with pytest.raises(exc_user.BadGroupSelection):
			f_user_mixin.ldap_user_update(
				username,
				{
					"groupsToAdd": ["CN=Group1"],
					"groupsToRemove": ["CN=Group1"],  # Same group
				},
				None,
			)

	def test_ldap_user_update_attribute_error(self, mocker, f_user_mixin: UserViewLDAPMixin, fc_user_entry, f_runtime_settings):
		"""Test attribute update failure"""
		mock_entry = fc_user_entry()
		mocker.patch.object(f_user_mixin, "get_user_entry", return_value=mock_entry)
		f_user_mixin.ldap_connection.modify.side_effect = Exception("Update failed")

		username = getattr(mock_entry, f_runtime_settings.LDAP_AUTH_USER_FIELDS["username"]).value[0]
		with pytest.raises(exc_user.UserUpdateError):
			f_user_mixin.ldap_user_update(username, {ldap_user.FIRST_NAME: "new_name"}, None)

	def test_ldap_user_update_lockout(self, mocker, f_user_mixin: UserViewLDAPMixin, fc_user_entry, f_runtime_settings):
		"""Test lockout time setting"""
		mock_entry = fc_user_entry()
		mocker.patch.object(f_user_mixin, "get_user_entry", return_value=mock_entry)
		mocker.patch.object(f_user_mixin, "ldap_user_update_keys", return_value=None)
		m_data = {ldap_user.FIRST_NAME: "new_name"}
		username = mock_entry.entry_attributes_as_dict[f_runtime_settings.LDAP_AUTH_USER_FIELDS["username"]][0]
		f_user_mixin.ldap_user_update(username, m_data, [LDAP_UF_LOCKOUT])
		f_user_mixin.ldap_user_update_keys.assert_called_once_with(
			user_dn=mock_entry.entry_attributes_as_dict["distinguishedName"][0],
			user_data=m_data | {"lockoutTime": 30, ldap_user.USER_ACCOUNT_CONTROL: calc_permissions([LDAP_UF_LOCKOUT])},
			replace_operation_keys=[
				ldap_user.FIRST_NAME, "lockoutTime", ldap_user.USER_ACCOUNT_CONTROL],
			delete_operation_keys=[]
		)

	# TODO
	# test group add
	# test group remove