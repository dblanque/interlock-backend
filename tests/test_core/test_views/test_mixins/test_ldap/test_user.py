import pytest
from core.views.mixins.ldap.user import UserViewLDAPMixin
from core.ldap.defaults import LDAP_AUTH_SEARCH_BASE, LDAP_DOMAIN
from core.ldap.adsi import LDAP_FILTER_AND, LDAP_FILTER_OR, LDAP_FILTER_NOT
from core.models.ldap_settings_runtime import RunningSettingsClass

@pytest.fixture
def f_user_mixin(mocker):
	mixin = UserViewLDAPMixin()
	mixin.ldap_connection = mocker.MagicMock()
	mixin.request = mocker.MagicMock()
	return mixin

@pytest.fixture
def f_mock_user_entry(mocker):
	mock = mocker.MagicMock()
	mock.distinguishedName = f"CN=test,OU=Users,{LDAP_AUTH_SEARCH_BASE}"
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

class TestUserViewLDAPMixin:
	@pytest.mark.parametrize(
		"test_kwargs, exclude_computers, expected",
		(
			(
				{
					"username":"testuser"
				},
				False,
				"({operator_and}(objectclass=person)({user_field}={identifier}))"
			),
			(
				{
					"username":"testuser"
				},
				True,
				"({operator_and}({operator_and}(objectclass=person)(!(objectclass=computer)))({user_field}={identifier}))"
			),
			(
				{
					"email":f"email@{LDAP_DOMAIN}"
				},
				False,
				"({operator_and}(objectclass=person)({email_field}={identifier}))"
			),
		),
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

	def test_get_user_object(self, mocker, f_user_mixin: UserViewLDAPMixin, f_ldap_search_base, f_auth_field_username):
		result = f_user_mixin.get_user_object(username="testuser")
		f_user_mixin.ldap_connection.search.assert_called_once_with(
			f_ldap_search_base,
			f"({LDAP_FILTER_AND}({LDAP_FILTER_AND}(objectclass=person)(!(objectclass=computer)))({f_auth_field_username}=testuser))",
			attributes=[f_auth_field_username, "distinguishedName"]
		)
		assert result == f_user_mixin.ldap_connection
