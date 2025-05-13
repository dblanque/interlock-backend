########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType
################################################################################
from core.ldap.security_identifier import SID
from core.models.ldap_object import LDAPObject
from core.constants.attrs import *
from core.ldap.filter import LDAPFilter
from ldap3 import (
	Entry as LDAPEntry,
	ALL_OPERATIONAL_ATTRIBUTES,
	ALL_ATTRIBUTES,
)
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton


@pytest.fixture(autouse=True)
def f_runtime_settings(
	mocker: MockerFixture, g_runtime_settings: RuntimeSettingsSingleton
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
def test_init_raises_kwarg_exception(object_args, expected_exc_msg_match):
	with pytest.raises(Exception, match=expected_exc_msg_match):
		LDAPObject(**object_args)


def test_init_no_validation(
		mocker: MockerFixture,
		f_runtime_settings: RuntimeSettingsSingleton
	):
	# Mock functions
	m_validate_init = mocker.patch.object(LDAPObject, "__validate_init__")
	m_set_kwargs = mocker.patch.object(LDAPObject, "__set_kwargs__")
	m_fetch_object = mocker.patch.object(LDAPObject, "__fetch_object__")
	m_sync_object = mocker.patch.object(LDAPObject, "__sync_object__")
	m_kwargs = {'some_kwarg': True}
	m_ldap_object = LDAPObject(**m_kwargs)
	assert not m_ldap_object.entry
	assert not m_ldap_object.connection
	assert not m_ldap_object.distinguished_name
	assert m_ldap_object.search_base == f_runtime_settings.LDAP_AUTH_SEARCH_BASE
	assert m_ldap_object.parsed_specials == []
	assert m_ldap_object.attributes == {}
	assert m_ldap_object.excluded_attributes == []
	m_validate_init.assert_called_once_with(**m_kwargs)
	m_set_kwargs.assert_called_once_with(**m_kwargs)
	m_fetch_object.assert_called_once()
	m_sync_object.assert_called_once()


def test_init_no_entry(
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
	assert m_ldap_object.excluded_attributes == []
	m_fetch_object.assert_called_once()
	m_sync_object.assert_called_once()


def test_init_with_entry(
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
	assert m_ldap_object.excluded_attributes == []
	m_fetch_object.assert_not_called()
	m_sync_object.assert_called_once()

def test_ddr_validate_init_raises_no_entry(mocker: MockerFixture):
	mocker.patch.object(LDAPObject, "__init__", return_value=None)
	m_ldap_object = LDAPObject()
	m_ldap_object.entry = False
	with pytest.raises(TypeError, match="type ldap3.Entry"):
		m_ldap_object.__validate_init__()

def test_ddr_validate_init_raises_entry_dn_bad_type(mocker: MockerFixture):
	mocker.patch.object(LDAPObject, "__init__", return_value=None)
	m_ldap_object = LDAPObject()
	m_entry = mocker.Mock(spec=LDAPEntry)
	m_entry.entry_dn = False
	m_ldap_object.entry = m_entry
	with pytest.raises(TypeError, match="type str"):
		m_ldap_object.__validate_init__()

def test_ddr_validate_init_no_connection(mocker: MockerFixture):
	mocker.patch.object(LDAPObject, "__init__", return_value=None)
	m_ldap_object = LDAPObject()
	m_ldap_object.connection = None
	m_ldap_object.entry = None
	with pytest.raises(Exception, match="LDAP Connection or Entry"):
		m_ldap_object.__validate_init__()

def test_ddr_validate_init_with_entry_dn(
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

def test_ddr_validate_init_raises_no_connection_or_entry(mocker: MockerFixture):
	mocker.patch.object(LDAPObject, "__init__", return_value=None)
	m_ldap_object = LDAPObject()
	m_ldap_object.distinguished_name = "mock_dn"

	with pytest.raises(Exception, match="requires an LDAP Connection or Entry"):
		m_ldap_object.__validate_init__()

def test_ddr_validate_init_raises_no_dn(mocker: MockerFixture, f_connection):
	mocker.patch.object(LDAPObject, "__init__", return_value=None)
	m_ldap_object = LDAPObject()
	m_ldap_object.connection = f_connection
	with pytest.raises(Exception, match="requires a Distinguished Name"):
		m_ldap_object.__validate_init__()

def test_ddr_validate_init_success(
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
	m_ldap_object.excluded_attributes = (LDAP_ATTR_FIRST_NAME,)
	m_ldap_object.__set_search_attrs__(search_attrs)
	assert m_ldap_object.search_attrs == expected

def test_ddr_set_search_attrs_is_falsy(mocker: MockerFixture):
	mocker.patch.object(LDAPObject, "__init__", return_value=None)
	m_ldap_object = LDAPObject()
	assert m_ldap_object.__set_search_attrs__(None) is None
	assert m_ldap_object.search_attrs == ALL_OPERATIONAL_ATTRIBUTES

def test_ddr_set_kwargs(mocker: MockerFixture):
	mocker.patch.object(LDAPObject, "__init__", return_value=None)
	m_set_search_attrs = mocker.patch.object(LDAPObject, "__set_search_attrs__")
	m_ldap_object = LDAPObject()
	m_ldap_object.__set_kwargs__(test=True)
	assert m_ldap_object.test is True
	m_set_search_attrs.assert_called_once_with(ALL_OPERATIONAL_ATTRIBUTES)

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
def test_ddr_get_methods(mocker, get_name_args):
	cls_attribute = get_name_args[1] or get_name_args[0]
	cls_method = get_name_args[0]
	mocker.patch.object(LDAPObject, "__init__", return_value=None)
	m_ldap_object = LDAPObject()
	setattr(m_ldap_object, cls_attribute, cls_attribute)
	method = getattr(m_ldap_object, f"__get_{cls_method}__")
	assert method() == cls_attribute

def test_ddr_sync_int_fields(mocker: MockerFixture):
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

# TODO

def test_ddr_sync_object_no_entry(mocker: MockerFixture):
	mocker.patch.object(LDAPObject, "__init__", return_value=None)
	m_object = LDAPObject()
	assert m_object.__sync_object__() is None

def test_ddr_sync_object(mocker: MockerFixture, f_object_entry_user: LDAPEntry):
	mocker.patch.object(LDAPObject, "__init__", return_value=None)
	m_object = LDAPObject()
	m_object.entry = f_object_entry_user()
	assert m_object.__sync_object__() is None
	assert m_object.attributes

# test fetch
# test ldap_attrs
# test get_local_alias_for_ldap_key
# test value_changed
# test create
# test update
# test delete
# test save

def test_ddr_get_common_name_extracts_cn_from_dn(
	f_object_args, f_connection
):
	# Setup
	object_args = f_object_args()
	test_dn = "CN=Test User,CN=Users,DC=example,DC=com"

	# Instantiate
	ldap_obj = LDAPObject(**object_args)

	# Execute
	result = ldap_obj.__get_common_name__(test_dn)

	# Assert
	assert result == "Test User"


def test_ddr_get_common_name_handles_empty_string(
	f_object_args, f_connection
):
	# Setup
	object_args = f_object_args()
	ldap_obj = LDAPObject(**object_args)

	# Execute
	result = ldap_obj.__get_common_name__("")

	# Assert
	assert result == ""


def test_ddr_get_common_name_handles_malformed_dn(
	f_object_args, f_connection
):
	# Setup
	object_args = f_object_args()
	ldap_obj = LDAPObject(**object_args)

	# Execute with malformed DN
	result = ldap_obj.__get_common_name__("not,a,proper,dn")

	# Assert
	assert result == "not"


def test_ddr_mapped_attrs(f_object_entry_user, f_object_args, f_connection, f_runtime_settings):
	# Setup
	object_args = f_object_args()
	ldap_obj = LDAPObject(**object_args)
	ldap_obj.connection.entries = [f_object_entry_user()]
	ldap_obj.__fetch_object__()

	result = ldap_obj.__mapped_attrs__()
	assert isinstance(result, dict)
	for _local_alias, _ldap_alias in f_runtime_settings.LDAP_FIELD_MAP.items():
		if not _local_alias in result:
			continue
		assert _ldap_alias in ldap_obj.attributes.keys()


def test_ddr_get_and_set_attrs(
	f_object_entry_user, f_object_args, f_connection
):
	# Setup
	object_args = f_object_args()
	ldap_obj = LDAPObject(**object_args)
	ldap_obj.connection.entries = [f_object_entry_user()]
	ldap_obj.__fetch_object__()

	# Test setting with local attr key
	setattr(ldap_obj, LOCAL_ATTR_FIRST_NAME, "John")
	# Test both fetches
	assert getattr(ldap_obj, LDAP_ATTR_FIRST_NAME) == "John"
	assert getattr(ldap_obj, LOCAL_ATTR_FIRST_NAME) == "John"

	# Test setting with LDAP attr key
	setattr(ldap_obj, LDAP_ATTR_LAST_NAME, "Smith")
	# Test both fetches
	assert getattr(ldap_obj, LDAP_ATTR_LAST_NAME) == "Smith"
	assert getattr(ldap_obj, LOCAL_ATTR_LAST_NAME) == "Smith"
