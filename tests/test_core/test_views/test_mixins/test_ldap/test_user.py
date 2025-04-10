import pytest
from core.views.mixins.ldap.user import UserViewLDAPMixin
from core.ldap.defaults import LDAP_DOMAIN
from core.ldap.adsi import (
	LDAP_FILTER_AND,
	LDAP_PERMS,
	LDAP_UF_ACCOUNT_DISABLE,
	LDAP_UF_DONT_EXPIRE_PASSWD,
	LDAP_UF_NORMAL_ACCOUNT,
)
from core.models.ldap_settings_runtime import RunningSettingsClass

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
def f_auth_field_username(f_runtime_settings: RunningSettingsClass):
	return f_runtime_settings.LDAP_AUTH_USER_FIELDS["username"]

@pytest.fixture
def f_auth_field_email(f_runtime_settings: RunningSettingsClass):
	return f_runtime_settings.LDAP_AUTH_USER_FIELDS["email"]

@pytest.fixture
def f_ldap_domain(f_runtime_settings: RunningSettingsClass):
	return f_runtime_settings.LDAP_DOMAIN

@pytest.fixture
def f_ldap_search_base(f_runtime_settings: RunningSettingsClass):
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
def fc_user_entry(mocker, f_ldap_search_base, f_auth_field_email, f_auth_field_username, f_ldap_domain):
	def maker(username, **kwargs):
		attrs = {
			f_auth_field_username: username,
			f_auth_field_email: f"{username}@{f_ldap_domain}",
			"distinguishedName": f"CN={username},OU=Users,{f_ldap_search_base}",
		} | kwargs
		mock = mocker.MagicMock()
		for k,v in attrs.items():
			setattr(mock, k, v)
		return mock
	return maker

@pytest.fixture
def f_group_dn(f_ldap_search_base):
	return f"CN=testgroup,OU=Groups,{f_ldap_search_base}"

class TestUserViewLDAPMixin:
	@pytest.mark.parametrize(
		"test_kwargs, exclude_computers, expected",
		(
			(
				{
					"username":"testuser"
				},
				False,
				"({operator_and}(objectClass=person)({user_field}={identifier}))"
			),
			(
				{
					"username":"testuser"
				},
				True,
				"({operator_and}({operator_and}(objectClass=person)(!(objectClass=computer)))({user_field}={identifier}))"
			),
			(
				{
					"email":f"email@{LDAP_DOMAIN}"
				},
				False,
				"({operator_and}(objectClass=person)({email_field}={identifier}))"
			),
		),
		ids=[
			"With Username Field",
			"With Email Field",
			"With Username Field, exclude computers",
		]
	)
	def test_get_user_object_filter_no_computers(
			self,
			test_kwargs: dict,
			exclude_computers,
			expected: str,
			f_user_mixin: UserViewLDAPMixin,
			f_runtime_settings: RunningSettingsClass,
			f_auth_field_email,
			f_auth_field_username,
		):
			expected = expected.format(
				operator_and=LDAP_FILTER_AND,
				user_field=f_auth_field_username,
				email_field=f_auth_field_email,
				identifier=test_kwargs.get("email", test_kwargs.get("username"))
			)
			f_runtime_settings.EXCLUDE_COMPUTER_ACCOUNTS = exclude_computers
			assert f_user_mixin.get_user_object_filter(**test_kwargs) == expected

	def test_get_user_object_filter_xor_raises(self, f_user_mixin: UserViewLDAPMixin):
		with pytest.raises(ValueError, match="XOR"):
			f_user_mixin.get_user_object_filter(username="a", email="b")

	def test_get_user_object(self, mocker, f_user_mixin: UserViewLDAPMixin, f_ldap_search_base, f_auth_field_username):
		result = f_user_mixin.get_user_object(username="testuser")
		f_user_mixin.ldap_connection.search.assert_called_once_with(
			f_ldap_search_base,
			f"({LDAP_FILTER_AND}({LDAP_FILTER_AND}(objectClass=person)(!(objectClass=computer)))({f_auth_field_username}=testuser))",
			attributes=[f_auth_field_username, "distinguishedName"]
		)
		assert result == f_user_mixin.ldap_connection

	def test_get_group_attributes(self, f_user_mixin: UserViewLDAPMixin, f_group_dn, mocker):
		m_group_attrs = ["some_attribute_list"]
		m_group = mocker.Mock()
		m_group.attributes = m_group_attrs
		m_ldap_object = mocker.patch("core.views.mixins.ldap.user.LDAPObject", return_value=m_group)

		result = f_user_mixin.get_group_attributes(groupDn=f_group_dn)
		m_ldap_object.assert_called_once_with(
			connection=f_user_mixin.ldap_connection,
			ldap_filter=f"({LDAP_FILTER_AND}(objectClass=group)(distinguishedName={f_group_dn}))",
			ldap_attrs=["objectSid"]
		)
		assert result == m_group_attrs

	def test_ldap_user_list(self, f_user_mixin: UserViewLDAPMixin, f_runtime_settings: RunningSettingsClass, fc_user_entry: dict, fc_user_permissions: int):
		m_entries = [
			fc_user_entry("testuser1", **{"userAccountControl": fc_user_permissions()}),
			fc_user_entry("testuser2", **{"userAccountControl": fc_user_permissions([LDAP_UF_ACCOUNT_DISABLE, LDAP_UF_NORMAL_ACCOUNT])}),
		]
		f_user_mixin.ldap_filter_object = "(objectclass=" + f_runtime_settings.LDAP_AUTH_OBJECT_CLASS + ")"
		f_user_mixin.ldap_filter_attr = f_user_mixin.filter_attr_builder(f_runtime_settings).get_list_attrs()
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
