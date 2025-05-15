########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture
################################################################################
from core.models.ldap_object import LDAPObject, LDAPObjectTypes
from core.constants.attrs import *
from core.ldap.filter import LDAPFilter
from core.views.mixins.utils import getldapattrvalue
from core.type_hints.connector import LDAPConnectionProtocol
from ldap3 import (
	Entry as LDAPEntry,
	ALL_OPERATIONAL_ATTRIBUTES,
	ALL_ATTRIBUTES,
	SUBTREE,
	MODIFY_DELETE,
	MODIFY_REPLACE,
)
from ldap3.core.exceptions import LDAPInvalidDnError
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton

@pytest.fixture
def f_user_expected_keys():
	return (
		LOCAL_ATTR_TYPE,
		LOCAL_ATTR_NAME,
		LOCAL_ATTR_DN,
		LOCAL_ATTR_FIRST_NAME,
		LOCAL_ATTR_LAST_NAME,
		LOCAL_ATTR_FULL_NAME,
		LOCAL_ATTR_USERNAME,
		LOCAL_ATTR_EMAIL,
		LOCAL_ATTR_PHONE,
		LOCAL_ATTR_ADDRESS,
		LOCAL_ATTR_POSTAL_CODE,
		LOCAL_ATTR_CITY,
		LOCAL_ATTR_STATE,
		LOCAL_ATTR_COUNTRY_DCC,
		LOCAL_ATTR_COUNTRY,
		LOCAL_ATTR_COUNTRY_ISO,
		LOCAL_ATTR_WEBSITE,
		LOCAL_ATTR_UPN,
		LOCAL_ATTR_UAC,
		LOCAL_ATTR_PRIMARY_GROUP_ID,
		LOCAL_ATTR_CREATED,
		LOCAL_ATTR_MODIFIED,
		LOCAL_ATTR_OBJECT_CLASS,
		LOCAL_ATTR_OBJECT_CATEGORY,
		LOCAL_ATTR_SECURITY_ID,
		LOCAL_ATTR_RELATIVE_ID,
		LOCAL_ATTR_LAST_LOGIN_WIN32,
		LOCAL_ATTR_BAD_PWD_COUNT,
		LOCAL_ATTR_PWD_SET_AT,
		LOCAL_ATTR_ACCOUNT_TYPE,
		LOCAL_ATTR_USER_GROUPS,
	)

@pytest.fixture(autouse=True)
def f_runtime_settings(
	mocker: MockerFixture,
	g_runtime_settings: RuntimeSettingsSingleton,
):
	return mocker.patch(
		"core.models.ldap_object.RuntimeSettings", g_runtime_settings
	)

@pytest.fixture
def f_object_args(f_connection, f_runtime_settings: RuntimeSettingsSingleton):
	def maker(**kwargs):
		return {
			"connection": f_connection,
			"distinguished_name": f"cn=testobject,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}",
			**kwargs,
		}

	return maker

class TestInit:
	@staticmethod
	@pytest.mark.parametrize(
		"object_args, expected_exc_msg_match",
		(
			({}, "requires an LDAP Connection"),
			({"connection": "something"}, "requires a Distinguished Name"),
		),
		ids=[
			"No LDAP Connection kwarg raises Exception",
			"No Distinguished Name kwarg raises Exception",
		],
	)
	def test_raises_kwarg_exception(
			object_args,
			expected_exc_msg_match
		):
		with pytest.raises(Exception, match=expected_exc_msg_match):
			LDAPObject(**object_args)

	@staticmethod
	def test_no_validation(
			mocker: MockerFixture,
			f_runtime_settings: RuntimeSettingsSingleton
		):
		# Mock functions
		m_validate_init = mocker.patch.object(LDAPObject, "__validate_init__")
		m_set_kwargs = mocker.patch.object(LDAPObject, "__set_kwargs__")
		m_fetch_object = mocker.patch.object(LDAPObject, "__fetch_object__")
		m_sync_object = mocker.patch.object(LDAPObject, "__sync_object__")
		
		# This is just to test that sub-functions are called with such kwargs.
		m_kwargs = {'some_kwarg': True}
		m_ldap_object = LDAPObject(**m_kwargs)

		assert not m_ldap_object.entry
		assert not m_ldap_object.connection
		assert not m_ldap_object.distinguished_name
		assert m_ldap_object.search_base == f_runtime_settings.LDAP_AUTH_SEARCH_BASE
		assert m_ldap_object.parsed_specials == []
		assert m_ldap_object.attributes == {}
		assert m_ldap_object.excluded_ldap_attributes == []
		m_validate_init.assert_called_once_with(**m_kwargs)
		m_set_kwargs.assert_called_once_with(**m_kwargs)
		m_fetch_object.assert_called_once()
		m_sync_object.assert_called_once()

	@staticmethod
	def test_no_entry(
			mocker: MockerFixture,
			f_runtime_settings: RuntimeSettingsSingleton,
			f_connection,
		):
		# Mock functions
		m_fetch_object = mocker.patch.object(LDAPObject, "__fetch_object__")
		m_sync_object = mocker.patch.object(LDAPObject, "__sync_object__")
		m_ldap_object = LDAPObject(
			connection=f_connection,
			distinguished_name="mock_dn"
		)
		assert not m_ldap_object.entry
		assert m_ldap_object.connection == f_connection
		assert m_ldap_object.distinguished_name == "mock_dn"
		assert m_ldap_object.search_base == f_runtime_settings.LDAP_AUTH_SEARCH_BASE
		assert m_ldap_object.parsed_specials == []
		assert m_ldap_object.attributes == {}
		assert m_ldap_object.excluded_ldap_attributes == []
		m_fetch_object.assert_called_once()
		m_sync_object.assert_called_once()

	@staticmethod
	def test_with_entry(
			mocker: MockerFixture,
			f_runtime_settings: RuntimeSettingsSingleton,
		):
		# Mock functions
		m_fetch_object = mocker.patch.object(LDAPObject, "__fetch_object__")
		m_sync_object = mocker.patch.object(LDAPObject, "__sync_object__")
		m_entry = mocker.Mock(spec=LDAPEntry)
		m_entry.entry_dn = "mock_dn"
		m_ldap_object = LDAPObject(entry=m_entry)
		assert m_ldap_object.entry == m_entry
		assert m_ldap_object.distinguished_name == m_entry.entry_dn
		assert not m_ldap_object.connection
		assert m_ldap_object.search_base == f_runtime_settings.LDAP_AUTH_SEARCH_BASE
		assert m_ldap_object.parsed_specials == []
		assert m_ldap_object.attributes == {}
		assert m_ldap_object.excluded_ldap_attributes == []
		m_fetch_object.assert_not_called()
		m_sync_object.assert_called_once()

class TestDunderValidateInit:
	@staticmethod
	def test_raises_no_entry(mocker: MockerFixture):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_ldap_object = LDAPObject()
		m_ldap_object.entry = False
		with pytest.raises(TypeError, match="type ldap3.Entry"):
			m_ldap_object.__validate_init__()

	@staticmethod
	def test_raises_entry_dn_bad_type(mocker: MockerFixture):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_ldap_object = LDAPObject()
		m_entry = mocker.Mock(spec=LDAPEntry)
		m_entry.entry_dn = False
		m_ldap_object.entry = m_entry
		with pytest.raises(TypeError, match="type str"):
			m_ldap_object.__validate_init__()

	@staticmethod
	def test_raises_no_connection(mocker: MockerFixture):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_ldap_object = LDAPObject()
		m_ldap_object.connection = None
		m_ldap_object.entry = None
		with pytest.raises(Exception, match="LDAP Connection or Entry"):
			m_ldap_object.__validate_init__()

	@staticmethod
	def test_raises_no_connection_or_entry(mocker: MockerFixture):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_ldap_object = LDAPObject()
		m_ldap_object.distinguished_name = "mock_dn"

		with pytest.raises(Exception, match="requires an LDAP Connection or Entry"):
			m_ldap_object.__validate_init__()

	@staticmethod
	def test_raises_no_dn(mocker: MockerFixture, f_connection):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_ldap_object = LDAPObject()
		m_ldap_object.connection = f_connection
		with pytest.raises(Exception, match="requires a Distinguished Name"):
			m_ldap_object.__validate_init__()

	@staticmethod
	def test_success(
		mocker: MockerFixture,
		f_connection,
		f_object_args,
	):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_ldap_object = LDAPObject()
		m_distinguished_name = "mock_dn"
		m_ldap_object.connection = f_connection
		m_ldap_object.distinguished_name = m_distinguished_name

		# With DN and connection
		m_ldap_object.__validate_init__()
		assert m_ldap_object.search_filter == LDAPFilter.eq(
			LDAP_ATTR_DN,
			m_distinguished_name
		).to_string()

		# With Entry
		m_ldap_object = LDAPObject()
		m_entry = mocker.Mock(spec=LDAPEntry)
		m_args = f_object_args()
		m_entry.entry_dn = m_args[LOCAL_ATTR_DN]
		m_ldap_object.entry = m_entry
		m_ldap_object.__validate_init__()
		assert m_ldap_object.search_filter == LDAPFilter.eq(
			LDAP_ATTR_DN,
			m_args[LOCAL_ATTR_DN]
		).to_string()

	@staticmethod
	def test_only_with_entry_dn(
		mocker: MockerFixture,
		f_object_args
	):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_ldap_object = LDAPObject()
		m_entry = mocker.Mock(spec=LDAPEntry)
		m_args = f_object_args()
		m_entry.entry_dn = m_args[LOCAL_ATTR_DN]
		m_ldap_object.entry = m_entry
		m_ldap_object.__validate_init__()
		assert m_ldap_object.search_filter == LDAPFilter.eq(
			LDAP_ATTR_DN,
			m_args[LOCAL_ATTR_DN]
		).to_string()

class TestDunderSetSearchAttrs:
	@staticmethod
	@pytest.mark.parametrize(
		"bad_value",
		(
			{"mock":"dict"},
			b"bytes",
		)
	)
	def test_ddr_set_search_attrs_raises_type_error(mocker: MockerFixture, bad_value):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_ldap_object = LDAPObject()
		with pytest.raises(TypeError):
			m_ldap_object.__set_search_attrs__(bad_value)

	@staticmethod
	@pytest.mark.parametrize(
		"search_attrs, expected",
		(
			(
				ALL_OPERATIONAL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
			),
			(
				ALL_ATTRIBUTES, ALL_ATTRIBUTES
			),
			(
				(LDAP_ATTR_DN, LDAP_ATTR_FIRST_NAME, LDAP_ATTR_LAST_NAME),
				(LDAP_ATTR_DN, LDAP_ATTR_LAST_NAME)
			),
			(
				(LDAP_ATTR_DN, LDAP_ATTR_USER_GROUPS),
				(LDAP_ATTR_DN, LDAP_ATTR_USER_GROUPS, LDAP_ATTR_PRIMARY_GROUP_ID)
			),
		),
	)
	def test_ddr_set_search_attrs(mocker: MockerFixture, search_attrs, expected):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_ldap_object = LDAPObject()
		m_ldap_object.excluded_ldap_attributes = (LDAP_ATTR_FIRST_NAME,)
		m_ldap_object.__set_search_attrs__(search_attrs)
		assert m_ldap_object.search_attrs == expected

	@staticmethod
	def test_ddr_set_search_attrs_is_falsy(mocker: MockerFixture):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_ldap_object = LDAPObject()
		assert m_ldap_object.__set_search_attrs__(None) is None
		assert m_ldap_object.search_attrs == ALL_OPERATIONAL_ATTRIBUTES

class TestDunderSetKwargs:
	@staticmethod
	def test_ddr_set_kwargs(mocker: MockerFixture):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_set_search_attrs = mocker.patch.object(LDAPObject, "__set_search_attrs__")
		m_ldap_object = LDAPObject()
		m_ldap_object.__set_kwargs__(test=True)
		assert m_ldap_object.test is True
		m_set_search_attrs.assert_called_once_with(ALL_OPERATIONAL_ATTRIBUTES)

class TestDunderGetMethods:
	@staticmethod
	@pytest.mark.parametrize(
		"get_name_args",
		(
			(
				"connection",
				None,
			),
			(
				"entry",
				None,
			),
			(
				"object",
				"attributes",
			),
		),
		ids=[
			"__get_connection__ returns connection",
			"__get_entry__ returns entry",
			"__get_object__ returns attributes",
		],
	)
	def test_get_methods(mocker, get_name_args):
		cls_attribute = get_name_args[1] or get_name_args[0]
		cls_method = get_name_args[0]
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_ldap_object = LDAPObject()
		setattr(m_ldap_object, cls_attribute, cls_attribute)
		method = getattr(m_ldap_object, f"__get_{cls_method}__")
		assert method() == cls_attribute

class TestDunderSyncIntFields:
	@staticmethod
	def test_success(mocker: MockerFixture):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		fields = (
			LOCAL_ATTR_COUNTRY_DCC,
			LOCAL_ATTR_UAC,
			LOCAL_ATTR_LAST_LOGIN_WIN32,
			LOCAL_ATTR_BAD_PWD_COUNT,
			LOCAL_ATTR_PWD_SET_AT,
			LOCAL_ATTR_PRIMARY_GROUP_ID,
			LOCAL_ATTR_RELATIVE_ID,
			LOCAL_ATTR_ACCOUNT_TYPE,
		)
		m_ldap_object = LDAPObject()
		m_ldap_object.attributes = { _key: str(1234) for _key in fields }
		m_ldap_object.__sync_int_fields__()
		for fld in fields:
			assert m_ldap_object.attributes[fld] == 1234

class TestDunderSyncObject:
	@staticmethod
	def test_no_entry(mocker: MockerFixture):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_object = LDAPObject()
		assert m_object.__sync_object__() is None

	@staticmethod
	def test_success(
		mocker: MockerFixture,
		f_object_entry_user: LDAPEntry,
		f_runtime_settings: RuntimeSettingsSingleton,
		f_user_expected_keys: tuple[str],
	):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_object = LDAPObject()
		m_object.entry = f_object_entry_user()
		assert m_object.__sync_object__() is None
		assert isinstance(m_object.attributes, dict)
		assert set(m_object.attributes.keys()) == set(f_user_expected_keys)
		mappable_keys = list(f_runtime_settings.LDAP_FIELD_MAP.keys())
		mappable_keys.append(LOCAL_ATTR_TYPE)
		for local_alias, value in m_object.attributes.items():
			ldap_alias = f_runtime_settings.LDAP_FIELD_MAP.get(local_alias)
			if local_alias == LOCAL_ATTR_TYPE:
				assert value == LDAPObjectTypes.PERSON.value.lower()
				continue
			elif local_alias == LOCAL_ATTR_RELATIVE_ID:
				assert value == 1105
				continue

			if ldap_alias in m_object.entry.entry_attributes:
				# Check if SID parsed correctly
				if local_alias == LOCAL_ATTR_SECURITY_ID:
					assert value == "S-1-5-21-2209570321-9700970-2859064192-1105"
				# Check all other attrs are mapped properly
				else:
					assert value == getldapattrvalue(m_object.entry, ldap_alias)

	@staticmethod
	def test_success_with_excluded_attr(
		mocker: MockerFixture,
		f_object_entry_user: LDAPEntry,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_object = LDAPObject()
		m_object.entry = f_object_entry_user()
		m_object.excluded_ldap_attributes = [LDAP_ATTR_ADDRESS]
		assert m_object.__sync_object__() is None
		assert LDAP_ATTR_ADDRESS in m_object.entry.entry_attributes
		assert LOCAL_ATTR_ADDRESS not in list(m_object.attributes.keys())

	@staticmethod
	def test_success_with_no_alias_attr(
		mocker: MockerFixture,
		f_object_entry_user: LDAPEntry,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		f_runtime_settings.LDAP_FIELD_MAP[LOCAL_ATTR_ADDRESS] = None
		m_object = LDAPObject()
		m_object.entry = f_object_entry_user()
		assert m_object.__sync_object__() is None
		assert LDAP_ATTR_ADDRESS in m_object.entry.entry_attributes
		assert LOCAL_ATTR_ADDRESS not in list(m_object.attributes.keys())

	@staticmethod
	def test_success_with_builtin_attr(
		mocker: MockerFixture,
		f_object_entry_user: LDAPEntry,
	):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_object = LDAPObject()
		m_object.entry = f_object_entry_user({
			LDAP_ATTR_OBJECT_CLASS: [
				"top",
				"person",
				"organizationalPerson",
				"user",
				"builtinDomain"
			]
		})
		assert m_object.__sync_object__() is None
		assert m_object.attributes[LOCAL_ATTR_BUILT_IN] is True

class TestDunderFetchObject:
	@staticmethod
	def test_success(mocker: MockerFixture, f_connection: LDAPConnectionProtocol):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_object = LDAPObject()
		m_entry = mocker.Mock()
		m_entry.entry_dn = "m_distinguished_name"
		m_object.connection = f_connection
		m_object.search_base = "m_search_base"
		m_object.search_filter = "m_search_filter"
		m_object.search_attrs = "m_search_attrs"
		m_object.connection.entries = [m_entry]

		# Execution
		m_object.__fetch_object__()

		# Assertions
		m_object.connection.search.assert_called_once_with(
			search_base=m_object.search_base,
			search_filter=m_object.search_filter,
			search_scope=SUBTREE,
			attributes=m_object.search_attrs,
		)
		assert m_object.fetched is True
		assert m_object.entry == m_entry
		assert m_object.distinguished_name == m_entry.entry_dn

	@staticmethod
	def test_no_result(mocker: MockerFixture, f_connection: LDAPConnectionProtocol):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_object = LDAPObject()
		m_object.connection = f_connection
		m_object.search_base = "m_search_base"
		m_object.search_filter = "m_search_filter"
		m_object.search_attrs = "m_search_attrs"
		m_object.connection.entries = []

		# Execution
		m_object.__fetch_object__()

		# Assertions
		m_object.connection.search.assert_called_once_with(
			search_base=m_object.search_base,
			search_filter=m_object.search_filter,
			search_scope=SUBTREE,
			attributes=m_object.search_attrs,
		)
		assert m_object.fetched is True
		assert not m_object.entry

	@staticmethod
	def test_more_than_one_result(
		mocker: MockerFixture,
		f_connection: LDAPConnectionProtocol
	):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_logger = mocker.patch("core.models.ldap_object.logger")
		m_object = LDAPObject()
		m_entry = mocker.Mock()
		m_entry.entry_dn = "m_distinguished_name"
		m_object.connection = f_connection
		m_object.search_base = "m_search_base"
		m_object.search_filter = "m_search_filter"
		m_object.search_attrs = "m_search_attrs"
		m_object.connection.entries = [m_entry, "mock_entry_2"]

		# Execution
		m_object.__fetch_object__()

		# Assertions
		m_object.connection.search.assert_called_once_with(
			search_base=m_object.search_base,
			search_filter=m_object.search_filter,
			search_scope=SUBTREE,
			attributes=m_object.search_attrs,
		)
		m_logger.warning.call_count == 2
		assert m_object.fetched is True
		assert m_object.entry == m_entry
		assert m_object.distinguished_name == m_entry.entry_dn

class TestGetCommonName:
	@staticmethod
	def test_ddr_get_common_name_extracts_cn_from_dn(
		mocker: MockerFixture,
	):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)

		# Setup
		test_dn = "CN=Test User,CN=Users,DC=example,DC=com"

		# Instantiate
		ldap_obj = LDAPObject()

		# Assert
		assert ldap_obj.__get_common_name__(test_dn) == "Test User"

	@staticmethod
	def test_ddr_get_common_name_extracts_cn_from_entry(
		mocker: MockerFixture,
	):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)

		# Instantiate
		ldap_obj = LDAPObject()
		ldap_obj.distinguished_name = "CN=Mock,DC=example,DC=com"

		# Assert
		assert ldap_obj.__get_common_name__() == "Mock"

	@staticmethod
	def test_ddr_get_common_name_raises_on_empty_string(mocker: MockerFixture):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		ldap_obj = LDAPObject()

		# Execute
		with pytest.raises(TypeError, match="of type str or None"):
			ldap_obj.__get_common_name__(b"bad_value")

	@staticmethod
	def test_ddr_get_common_name_raises_on_malformed_dn(mocker: MockerFixture):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)

		# Setup
		ldap_obj = LDAPObject()

		# Execute with malformed DN
		with pytest.raises(LDAPInvalidDnError):
			ldap_obj.__get_common_name__("not,a,proper,dn")

class TestGetLocalAliasForLDAPKey:
	@staticmethod
	@pytest.mark.parametrize(
		"local_alias, ldap_alias",
		(
			(LOCAL_ATTR_DN, LDAP_ATTR_DN,),
			(LOCAL_ATTR_USERNAME, LDAP_ATTR_USERNAME_SAMBA_ADDS,),
			(LOCAL_ATTR_EMAIL, LDAP_ATTR_EMAIL,),
			(LOCAL_ATTR_PASSWORD, LDAP_ATTR_PASSWORD,),
			(LOCAL_ATTR_FIRST_NAME, LDAP_ATTR_FIRST_NAME,),
			(LOCAL_ATTR_LAST_NAME, LDAP_ATTR_LAST_NAME,),
			(LOCAL_ATTR_FULL_NAME, LDAP_ATTR_FULL_NAME,),
			(LOCAL_ATTR_INITIALS, LDAP_ATTR_INITIALS,),
			(LOCAL_ATTR_PHONE, LDAP_ATTR_PHONE,),
			(LOCAL_ATTR_ADDRESS, LDAP_ATTR_ADDRESS,),
			(LOCAL_ATTR_POSTAL_CODE, LDAP_ATTR_POSTAL_CODE,),
			(LOCAL_ATTR_CITY, LDAP_ATTR_CITY,),
			(LOCAL_ATTR_STATE, LDAP_ATTR_STATE,),
			(LOCAL_ATTR_COUNTRY, LDAP_ATTR_COUNTRY,),
			(LOCAL_ATTR_COUNTRY_DCC, LDAP_ATTR_COUNTRY_DCC,),
			(LOCAL_ATTR_COUNTRY_ISO, LDAP_ATTR_COUNTRY_ISO,),
			(LOCAL_ATTR_WEBSITE, LDAP_ATTR_WEBSITE,),
			(LOCAL_ATTR_UPN, LDAP_ATTR_UPN,),
			(LOCAL_ATTR_UAC, LDAP_ATTR_UAC,),
			(LOCAL_ATTR_CREATED, LDAP_ATTR_CREATED,),
			(LOCAL_ATTR_MODIFIED, LDAP_ATTR_MODIFIED,),
			(LOCAL_ATTR_LAST_LOGIN_WIN32, LDAP_ATTR_LAST_LOGIN,),
			(LOCAL_ATTR_BAD_PWD_COUNT, LDAP_ATTR_BAD_PWD_COUNT,),
			(LOCAL_ATTR_PWD_SET_AT, LDAP_ATTR_PWD_SET_AT,),
			(LOCAL_ATTR_PRIMARY_GROUP_ID, LDAP_ATTR_PRIMARY_GROUP_ID,),
			(LOCAL_ATTR_OBJECT_CLASS, LDAP_ATTR_OBJECT_CLASS,),
			(LOCAL_ATTR_OBJECT_CATEGORY, LDAP_ATTR_OBJECT_CATEGORY,),
			(LOCAL_ATTR_RELATIVE_ID, LDAP_ATTR_RELATIVE_ID,),
			(LOCAL_ATTR_SECURITY_ID, LDAP_ATTR_SECURITY_ID,),
			(LOCAL_ATTR_ACCOUNT_TYPE, LDAP_ATTR_ACCOUNT_TYPE,),
			(LOCAL_ATTR_USER_GROUPS, LDAP_ATTR_USER_GROUPS,),
			(LOCAL_ATTR_GROUP_MEMBERS, LDAP_ATTR_GROUP_MEMBERS,),
			(LOCAL_ATTR_LOGON_TIMESTAMP, LDAP_ATTR_LOGON_TIMESTAMP,),
			(LOCAL_ATTR_EXPIRES_AT, LDAP_ATTR_EXPIRES_AT,),
			(LOCAL_ATTR_NAME, LDAP_ATTR_COMMON_NAME,),
			(LOCAL_ATTR_GROUP_TYPE, LDAP_ATTR_GROUP_TYPE,),
		),
	)
	def test_success(
		local_alias: str,
		ldap_alias: str,
		mocker: MockerFixture,
	):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		ldap_obj = LDAPObject()
		assert ldap_obj.get_local_alias_for_ldap_key(ldap_alias) == local_alias

	@staticmethod
	def test_raises_value_error(mocker: MockerFixture):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		ldap_obj = LDAPObject()
		with pytest.raises(ValueError):
			ldap_obj.get_local_alias_for_ldap_key("some_bad_key")

	@staticmethod
	def test_returns_args_default(mocker: MockerFixture):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		ldap_obj = LDAPObject()
		assert ldap_obj.get_local_alias_for_ldap_key(
			"some_bad_key", "mock_default") == "mock_default"

	@staticmethod
	def test_returns_kwargs_default(mocker: MockerFixture):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		ldap_obj = LDAPObject()
		assert ldap_obj.get_local_alias_for_ldap_key(
			"some_bad_key", default="mock_default") == "mock_default"

class TestExistsProperty:
	@staticmethod
	def test_success(
		mocker: MockerFixture,
		f_connection: LDAPConnectionProtocol,
	):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		mocker.patch.object(LDAPObject, "__fetch_object__", return_value=None)
		ldap_obj = LDAPObject()
		ldap_obj.connection = f_connection
		ldap_obj.entry = "mock_entry"
		assert ldap_obj.exists is True

	@staticmethod
	def test_raises_no_connection(mocker: MockerFixture):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		mocker.patch.object(LDAPObject, "__fetch_object__", return_value=None)
		ldap_obj = LDAPObject()
		ldap_obj.connection = None
		with pytest.raises(Exception, match="LDAP Connection is required"):
			ldap_obj.exists

	@staticmethod
	def test_raises_connection_not_bound(
		mocker: MockerFixture,
		f_connection: LDAPConnectionProtocol,
	):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		mocker.patch.object(LDAPObject, "__fetch_object__", return_value=None)
		ldap_obj = LDAPObject()
		ldap_obj.connection = f_connection
		ldap_obj.connection.bound = False
		with pytest.raises(Exception, match="must be bound"):
			ldap_obj.exists

class TestValueChanged:
	@staticmethod
	@pytest.mark.parametrize(
		"local_alias, ldap_alias, expected_exc",
		(
			("", None, "local_alias is falsy or unmapped",),
			(None, None, "local_alias is falsy or unmapped",),
			(LOCAL_ATTR_DN, "", "ldap_alias is falsy or unmapped",),
			(LOCAL_ATTR_DN, None, "ldap_alias is falsy or unmapped",),
		),
	)
	def test_raises_value_error(
		mocker: MockerFixture,
		local_alias: str,
		ldap_alias: str,
		expected_exc: str,
	):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_object = LDAPObject()
		with pytest.raises(ValueError, match=expected_exc):
			m_object.value_changed(local_alias, ldap_alias)

	@staticmethod
	@pytest.mark.parametrize(
		"local_alias, ldap_alias",
		(
			(b"bad_type", LDAP_ATTR_DN,),
			(LOCAL_ATTR_DN, b"bad_type",),
		),
	)
	def test_raises_type_error(
		mocker: MockerFixture,
		local_alias: str,
		ldap_alias: str,
	):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_object = LDAPObject()
		with pytest.raises(TypeError, match="must be of type str"):
			m_object.value_changed(local_alias, ldap_alias)

	@staticmethod
	@pytest.mark.parametrize(
		"local_alias, entry_value, local_value",
		(
			# str
			(LOCAL_ATTR_FIRST_NAME, "Test", "Changed"),
			# int
			(LOCAL_ATTR_BAD_PWD_COUNT, 0, 1),
			# bool
			(LOCAL_ATTR_BAD_PWD_COUNT, True, False),
			# list
			(LOCAL_ATTR_OBJECT_CLASS, ["person"], ["person", "user"]),
			# list with local as str
			(LOCAL_ATTR_OBJECT_CLASS, ["person"], "user"),
			# list with ldap as str
			(LOCAL_ATTR_OBJECT_CLASS, "person", ["person", "user"]),
		),
	)
	def test_should_return_true(
		local_alias: str,
		entry_value,
		local_value,
		f_runtime_settings: RuntimeSettingsSingleton,
		mocker: MockerFixture,
	):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_object = LDAPObject()
		ldap_alias = f_runtime_settings.LDAP_FIELD_MAP.get(local_alias)
		m_entry = mocker.Mock()
		m_entry_attr = mocker.Mock()
		m_entry_attr.value = entry_value
		m_entry_attr.values = entry_value
		setattr(m_entry, ldap_alias, m_entry_attr)
		m_object.entry = m_entry
		m_object.attributes = {local_alias: local_value}
		assert getldapattrvalue(m_entry, ldap_alias) == entry_value
		assert m_object.attributes.get(local_alias) == local_value
		assert m_object.value_changed(local_alias, ldap_alias)

	@staticmethod
	@pytest.mark.parametrize(
		"local_alias, entry_value",
		(
			# str
			(LOCAL_ATTR_FIRST_NAME, "Test"),
			# int
			(LOCAL_ATTR_BAD_PWD_COUNT, 0),
			# bool
			(LOCAL_ATTR_BAD_PWD_COUNT, False),
			# bool
			(LOCAL_ATTR_BAD_PWD_COUNT, True),
			# list
			(LOCAL_ATTR_OBJECT_CLASS, ["person"]),
			# any
			(LOCAL_ATTR_FIRST_NAME, None),
		),
	)
	def test_should_return_false(
		local_alias: str,
		entry_value,
		f_runtime_settings: RuntimeSettingsSingleton,
		mocker: MockerFixture,
	):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_object = LDAPObject()
		ldap_alias = f_runtime_settings.LDAP_FIELD_MAP.get(local_alias)
		m_entry = mocker.Mock()
		m_entry_attr = mocker.Mock()
		m_entry_attr.value = entry_value
		m_entry_attr.values = entry_value
		setattr(m_entry, ldap_alias, m_entry_attr)
		m_object.entry = m_entry
		m_object.attributes = {local_alias: entry_value}
		assert getldapattrvalue(m_entry, ldap_alias) == entry_value
		assert m_object.attributes.get(local_alias) == entry_value
		assert not m_object.value_changed(local_alias, ldap_alias)

class TestCreate:
	@staticmethod
	def test_raises_existing_entry(mocker: MockerFixture):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		ldap_obj = LDAPObject()
		ldap_obj.entry = mocker.Mock(name="m_entry")
		with pytest.raises(Exception, match="existing LDAP Entry"):
			ldap_obj.create()

	@staticmethod
	def test_success_user_ldap_object(
		mocker: MockerFixture,
		f_connection: LDAPConnectionProtocol,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_parse_write_special_attributes = mocker.patch.object(
			LDAPObject,
			"parse_write_special_attributes"
		)
		m_pre_create = mocker.patch.object(LDAPObject, "pre_create")
		m_post_create = mocker.patch.object(LDAPObject, "post_create")
		ldap_obj = LDAPObject()
		ldap_obj.distinguished_name = "mock_dn"
		ldap_obj.connection = f_connection
		m_result = mocker.Mock(name="m_result")
		m_result.description = "success"
		ldap_obj.connection.result = m_result
		ldap_obj.entry = None
		ldap_obj.parsed_specials = []
		ldap_obj.type = LDAPObjectTypes.USER
		ldap_obj.attributes = {
			LOCAL_ATTR_FIRST_NAME: "Test",
			LOCAL_ATTR_LAST_NAME: "User",
			LOCAL_ATTR_FULL_NAME: "Test User",
			LOCAL_ATTR_PHONE: "+5491112345678",
			LOCAL_ATTR_ADDRESS: "Mock Address 1234",
			LOCAL_ATTR_POSTAL_CODE: "CODE1234",
			# Special User attr that cannot be parsed by LDAPObject super-class
			LOCAL_ATTR_COUNTRY: "Argentina",
			# Attribute that is immutable
			LOCAL_ATTR_SECURITY_ID: "SID_IS_IMMUTABLE",
		}

		# Execution & Assertions
		assert ldap_obj.create() is True
		m_parse_write_special_attributes.assert_called_once()
		ldap_obj.connection.add.assert_called_once_with(
			dn=ldap_obj.distinguished_name,
			object_class=f_runtime_settings.LDAP_AUTH_OBJECT_CLASS,
			attributes={
				LDAP_ATTR_FIRST_NAME: "Test",
				LDAP_ATTR_LAST_NAME: "User",
				LDAP_ATTR_FULL_NAME: "Test User",
				LDAP_ATTR_PHONE: "+5491112345678",
				LDAP_ATTR_ADDRESS: "Mock Address 1234",
				LDAP_ATTR_POSTAL_CODE: "CODE1234",
				LDAP_ATTR_OBJECT_CLASS: list({
				f_runtime_settings.LDAP_AUTH_OBJECT_CLASS,
					"top",
					"person",
					"organizationalPerson",
					"user",
				}),
			},
		)
		m_pre_create.assert_called_once()
		m_post_create.assert_called_once()

	@staticmethod
	def test_success_group_ldap_object(
		mocker: MockerFixture,
		f_connection: LDAPConnectionProtocol,
	):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_parse_write_special_attributes = mocker.patch.object(
			LDAPObject,
			"parse_write_special_attributes"
		)
		m_pre_create = mocker.patch.object(LDAPObject, "pre_create")
		m_post_create = mocker.patch.object(LDAPObject, "post_create")
		ldap_obj = LDAPObject()
		ldap_obj.distinguished_name = "mock_dn"
		ldap_obj.connection = f_connection
		m_result = mocker.Mock(name="m_result")
		m_result.description = "success"
		ldap_obj.connection.result = m_result
		ldap_obj.entry = None
		ldap_obj.parsed_specials = []
		ldap_obj.type = LDAPObjectTypes.GROUP
		ldap_obj.attributes = {
			LOCAL_ATTR_NAME: "Test Group",
			LOCAL_ATTR_EMAIL: "mail@example.com",
			# Special Group attrs that cannot be parsed by LDAPObject
			LOCAL_ATTR_GROUP_TYPE: ["some_type"],
			LOCAL_ATTR_GROUP_SCOPE: ["some_scope"],
			LOCAL_ATTR_GROUP_MEMBERS: ["member_01", "member_02"],
			# Attribute that is immutable
			LOCAL_ATTR_SECURITY_ID: "SID_IS_IMMUTABLE",
		}

		# Execution & Assertions
		assert ldap_obj.create() is True
		m_parse_write_special_attributes.assert_called_once()
		ldap_obj.connection.add.assert_called_once_with(
			dn=ldap_obj.distinguished_name,
			object_class="group",
			attributes={
				LDAP_ATTR_EMAIL: "mail@example.com",
				LDAP_ATTR_OBJECT_CLASS: list({
					"top",
					"group",
				}),
			},
		)
		m_pre_create.assert_called_once()
		m_post_create.assert_called_once()

class TestUpdate:
	@staticmethod
	def test_raises_no_existing_entry(mocker: MockerFixture):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		ldap_obj = LDAPObject()
		ldap_obj.entry = None
		with pytest.raises(Exception, match="existing LDAP Entry is required"):
			ldap_obj.update()

	@staticmethod
	def test_raises_entry_type_error(mocker: MockerFixture):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		ldap_obj = LDAPObject()
		ldap_obj.entry = {"some": "dict"}
		with pytest.raises(TypeError, match="must be of type ldap3.Entry"):
			ldap_obj.update()

	@staticmethod
	def test_raises_attributes_must_be_set(mocker: MockerFixture):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		ldap_obj = LDAPObject()
		ldap_obj.entry = mocker.Mock(spec=LDAPEntry)
		with pytest.raises(ValueError, match="attributes must be set"):
			ldap_obj.update()

	@staticmethod
	def test_success(
		mocker: MockerFixture,
		f_connection: LDAPConnectionProtocol,
		f_object_entry_user,
	):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_parse_write_special_attributes = mocker.patch.object(
			LDAPObject,
			"parse_write_special_attributes"
		)
		m_pre_update = mocker.patch.object(LDAPObject, "pre_update")
		m_post_update = mocker.patch.object(LDAPObject, "post_update")
		ldap_obj = LDAPObject()
		ldap_obj.entry = f_object_entry_user()
		ldap_obj.distinguished_name = ldap_obj.entry.entry_dn
		ldap_obj.connection = f_connection
		m_result = mocker.Mock(name="m_result")
		m_result.description = "success"
		ldap_obj.connection.result = m_result
		ldap_obj.parsed_specials = []
		ldap_obj.type = LDAPObjectTypes.USER
		ldap_obj.attributes = {
			LOCAL_ATTR_PHONE: "",
			LOCAL_ATTR_ADDRESS: "Mock Address 1234",
			LOCAL_ATTR_POSTAL_CODE: None,
		}

		# Execution & Assertions
		assert ldap_obj.update() is True
		m_parse_write_special_attributes.assert_called_once()
		ldap_obj.connection.modify.assert_called_once_with(
			dn=ldap_obj.distinguished_name,
			changes={
				LDAP_ATTR_ADDRESS: [(MODIFY_REPLACE, ["Mock Address 1234"])],
				LDAP_ATTR_PHONE: [(MODIFY_DELETE, [])],
				LDAP_ATTR_POSTAL_CODE: [(MODIFY_DELETE, [])],
			},
		)
		m_pre_update.assert_called_once()
		m_post_update.assert_called_once()

class TestDelete:
	@staticmethod
	def test_success_delete_from_entry_dn(
		mocker: MockerFixture,
		f_connection: LDAPConnectionProtocol,
	):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_pre_delete = mocker.patch.object(LDAPObject, "pre_delete")
		m_post_delete = mocker.patch.object(LDAPObject, "post_delete")
		m_entry = mocker.Mock(spec=LDAPEntry)
		m_entry.entry_dn = "mock_dn"
		ldap_obj = LDAPObject()
		ldap_obj.entry = m_entry
		f_connection.result = mocker.Mock(name="m_result")
		f_connection.result.description = "success"
		ldap_obj.connection = f_connection

		assert ldap_obj.delete() is True
		ldap_obj.connection.delete.assert_called_once_with(
			dn=m_entry.entry_dn
		)
		m_pre_delete.assert_called_once()
		m_post_delete.assert_called_once()

	@staticmethod
	def test_success_delete_from_self_dn(
		mocker: MockerFixture,
		f_connection: LDAPConnectionProtocol,
	):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_pre_delete = mocker.patch.object(LDAPObject, "pre_delete")
		m_post_delete = mocker.patch.object(LDAPObject, "post_delete")
		ldap_obj = LDAPObject()
		ldap_obj.distinguished_name = "mock_dn"
		f_connection.result = mocker.Mock(name="m_result")
		f_connection.result.description = "success"
		ldap_obj.connection = f_connection

		assert ldap_obj.delete() is True
		ldap_obj.connection.delete.assert_called_once_with(
			dn=ldap_obj.distinguished_name
		)
		m_pre_delete.assert_called_once()
		m_post_delete.assert_called_once()

	@staticmethod
	def test_raises_entry_or_dn_required(
		mocker: MockerFixture,
		f_connection: LDAPConnectionProtocol,
	):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_pre_delete = mocker.patch.object(LDAPObject, "pre_delete")
		m_post_delete = mocker.patch.object(LDAPObject, "post_delete")
		ldap_obj = LDAPObject()
		ldap_obj.connection = f_connection

		with pytest.raises(Exception, match="requires a valid dn or entry"):
			ldap_obj.delete()
		ldap_obj.connection.delete.assert_not_called()
		m_pre_delete.assert_not_called()
		m_post_delete.assert_not_called()

class TestSave:
	@staticmethod
	def test_raises_exception(mocker: MockerFixture):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		mocker.patch.object(LDAPObject, "create", return_value=False)
		mocker.patch.object(LDAPObject, "update", return_value=False)
		ldap_obj = LDAPObject()
		ldap_obj.connection = None
		ldap_obj.entry = None
		with pytest.raises(Exception, match="requires a bound LDAP Connection"):
			ldap_obj.save()

	@staticmethod
	def test_success_create(
		mocker: MockerFixture,
		f_connection: LDAPConnectionProtocol,
	):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_create = mocker.patch.object(LDAPObject, "create", return_value=True)
		m_update = mocker.patch.object(LDAPObject, "update", return_value=True)
		ldap_obj = LDAPObject()
		ldap_obj.connection = f_connection
		ldap_obj.entry = None

		assert ldap_obj.save()
		m_create.assert_called_once()
		m_update.assert_not_called()

	@staticmethod
	def test_success_update(
		mocker: MockerFixture,
		f_connection: LDAPConnectionProtocol,
	):
		mocker.patch.object(LDAPObject, "__init__", return_value=None)
		m_create = mocker.patch.object(LDAPObject, "create", return_value=True)
		m_update = mocker.patch.object(LDAPObject, "update", return_value=True)
		ldap_obj = LDAPObject()
		ldap_obj.connection = f_connection
		ldap_obj.entry = "mock_entry"

		assert ldap_obj.save()
		m_create.assert_not_called()
		m_update.assert_called_once()
