########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture

################################################################################
from datetime import datetime
from core.views.mixins.utils import is_non_str_iterable
from core.constants.attrs import *
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from tests.test_core.conftest import RuntimeSettingsFactory
from ldap3 import Attribute as LDAPAttribute, Entry as LDAPEntry


@pytest.fixture(autouse=True)
def f_runtime_settings(
	mocker: MockerFixture,
	g_runtime_settings: RuntimeSettingsFactory,
):
	mock = g_runtime_settings()
	mocker.patch("core.models.ldap_object.RuntimeSettings", mock)
	mocker.patch("core.models.ldap_user.RuntimeSettings", mock)
	mocker.patch("core.models.ldap_group.RuntimeSettings", mock)
	mocker.patch("core.views.mixins.utils.RuntimeSettings", mock)
	return mock


@pytest.fixture
def f_object_attrs_user(f_runtime_settings: RuntimeSettingsSingleton) -> dict:
	def maker(**kwargs):
		fake_date = datetime.today().strftime(LDAP_DATE_FORMAT)
		fake_user = {
			LDAP_ATTR_DN: f"CN=Test User,OU=Administrators,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}",
			LDAP_ATTR_FIRST_NAME: "Test",
			LDAP_ATTR_LAST_NAME: "User",
			LDAP_ATTR_FULL_NAME: "Test User",
			LDAP_ATTR_USERNAME_SAMBA_ADDS: "testuser",
			LDAP_ATTR_EMAIL: f"testuser@{f_runtime_settings.LDAP_DOMAIN}",
			LDAP_ATTR_PHONE: "+5491112345678",
			LDAP_ATTR_ADDRESS: "Street Address Example",
			LDAP_ATTR_POSTAL_CODE: "POSTALCODE",
			LDAP_ATTR_CITY: "Some Town",
			LDAP_ATTR_STATE: "Buenos Aires",
			LDAP_ATTR_COUNTRY_DCC: 32,
			LDAP_ATTR_COUNTRY: "Argentina",
			LDAP_ATTR_COUNTRY_ISO: "AR",
			LDAP_ATTR_WEBSITE: f"https://{f_runtime_settings.LDAP_DOMAIN}",
			LDAP_ATTR_UPN: f"testuser@{f_runtime_settings.LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN}",
			LDAP_ATTR_UAC: 66048,
			LDAP_ATTR_PRIMARY_GROUP_ID: 513,
			LDAP_ATTR_CREATED: fake_date,
			LDAP_ATTR_MODIFIED: fake_date,
			LDAP_ATTR_OBJECT_CLASS: [
				"top",
				"person",
				"organizationalPerson",
				"user",
			],
			LDAP_ATTR_OBJECT_CATEGORY: f"CN=Person,CN=Schema,CN=Configuration,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}",
			# Expected SID: "S-1-5-21-123456789-1234567890-123456789-1105"
			LDAP_ATTR_SECURITY_ID: b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x11^\xb3\x83j\x06\x94\x00\x80\xdbi\xaaQ\x04\x00\x00",
			LDAP_ATTR_RELATIVE_ID: 1105,
			LDAP_ATTR_LAST_LOGIN: "fake_logon_date",
			LDAP_ATTR_BAD_PWD_COUNT: 0,
			LDAP_ATTR_PWD_SET_AT: "fake_pwd_last_set",
			LDAP_ATTR_ACCOUNT_TYPE: 805306368,
			LDAP_ATTR_USER_GROUPS: [
				f"CN=Administrators,CN=Builtin,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}",
				f"CN=Some Group,OU=Some OU,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}",
			],
		}
		for kw, val in kwargs.items():
			fake_user[kw] = val
		return fake_user

	return maker


@pytest.fixture
def f_object_attrs_group(f_runtime_settings: RuntimeSettingsSingleton) -> dict:
	def maker():
		return {
			LDAP_ATTR_DN: f"CN=Test Group,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}",
			LDAP_ATTR_SECURITY_ID: b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x11^\xb3\x83j\x06\x94\x00\x80\xdbi\xaaR\x04\x00\x00",
			LDAP_ATTR_RELATIVE_ID: 1106,
			LDAP_ATTR_OBJECT_CATEGORY: f"CN=Group,CN=Schema,CN=Configuration,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}",
			LDAP_ATTR_OBJECT_CLASS: ["top", "group"],
		}

	return maker


class FakeLDAPUserEntry:
	def __new__(cls):
		for attr in (
			LDAP_ATTR_DN,
			LDAP_ATTR_FIRST_NAME,
			LDAP_ATTR_LAST_NAME,
			LDAP_ATTR_FULL_NAME,
			LDAP_ATTR_USERNAME_SAMBA_ADDS,
			LDAP_ATTR_EMAIL,
			LDAP_ATTR_PHONE,
			LDAP_ATTR_ADDRESS,
			LDAP_ATTR_POSTAL_CODE,
			LDAP_ATTR_CITY,
			LDAP_ATTR_STATE,
			LDAP_ATTR_COUNTRY_DCC,
			LDAP_ATTR_COUNTRY,
			LDAP_ATTR_COUNTRY_ISO,
			LDAP_ATTR_WEBSITE,
			LDAP_ATTR_UPN,
			LDAP_ATTR_UAC,
			LDAP_ATTR_PRIMARY_GROUP_ID,
			LDAP_ATTR_CREATED,
			LDAP_ATTR_MODIFIED,
			LDAP_ATTR_OBJECT_CLASS,
			LDAP_ATTR_OBJECT_CATEGORY,
			LDAP_ATTR_SECURITY_ID,
			LDAP_ATTR_RELATIVE_ID,
			LDAP_ATTR_LAST_LOGIN,
			LDAP_ATTR_BAD_PWD_COUNT,
			LDAP_ATTR_PWD_SET_AT,
			LDAP_ATTR_ACCOUNT_TYPE,
			LDAP_ATTR_USER_GROUPS,
		):
			setattr(cls, attr, None)


@pytest.fixture
def f_object_entry_user(f_object_attrs_user, mocker: MockerFixture):
	def maker(attrs=None, **kwargs):
		if not attrs:
			attrs = {}
		m_attrs: dict = f_object_attrs_user() | attrs
		m_entry = mocker.Mock(spec=LDAPEntry)
		for attr, val in m_attrs.items():
			m_attr = mocker.Mock(spec=LDAPAttribute)
			m_attr.value = val
			if is_non_str_iterable(val):
				m_attr.values = val
			elif isinstance(val, (bytes, bytearray)):
				m_attr.raw_values = [val]
			else:
				m_attr.values = [val]
				m_attr.value = val
			setattr(m_entry, attr, m_attr)
		m_entry.entry_attributes = [*set(m_attrs.keys())]
		m_entry.entry_dn = m_attrs[LDAP_ATTR_DN]
		return m_entry

	return maker


@pytest.fixture
def f_object_entry_group(f_object_attrs_group, mocker: MockerFixture):
	def maker(attrs=None, **kwargs):
		if not attrs:
			attrs = {}
		m_attrs: dict = f_object_attrs_group() | attrs
		m_entry = mocker.Mock()
		for attr, val in m_attrs.items():
			m_attr = mocker.Mock(spec=LDAPAttribute)
			m_attr.values = val
			if is_non_str_iterable(val):
				m_attr.value = val if len(val) > 1 else val[0]
			else:
				m_attr.value = val
			setattr(m_entry, attr, m_attr)
		m_entry.entry_attributes = [*set(m_attrs.keys())]
		m_entry.entry_dn = m_attrs["distinguishedName"]
		return m_entry

	return maker


@pytest.fixture
def f_object_args(f_connection, f_runtime_settings: RuntimeSettingsSingleton):
	def maker(**kwargs):
		return {
			"connection": f_connection,
			"distinguished_name": f"cn=testobject,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}",
			**kwargs,
		}

	return maker
