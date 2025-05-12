########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType

################################################################################
from core.ldap.security_identifier import SID
from core.models.ldap_object import (
	LDAPObject,
	DEFAULT_REQUIRED_LDAP_ATTRS,
	DEFAULT_CONTAINER_TYPES,
)
from core.constants.attrs import (
	LDAP_ATTR_FIRST_NAME,
	LOCAL_ATTR_FIRST_NAME,
	LDAP_ATTR_LAST_NAME,
	LOCAL_ATTR_LAST_NAME,
)
from core.views.mixins.utils import is_non_str_iterable
from copy import deepcopy
from ldap3 import Attribute as LDAPAttribute
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


@pytest.fixture
def f_object_attrs_user(f_runtime_settings: RuntimeSettingsSingleton) -> dict:
	def maker():
		return {
			"name": "Test User",
			"distinguishedName": f"CN=Test User,OU=Administrators,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}",
			"type": "Person",
			"givenName": "Test",
			"sn": "User",
			"displayName": "Test User",
			"sAMAccountName": "testuser",
			"username": "testuser",
			"mail": f"testuser@{f_runtime_settings.LDAP_DOMAIN}",
			"telephoneNumber": "+5491112345678",
			"streetAddress": "Street Address Example",
			"postalCode": "POSTALCODE",
			"l": "Some Town",
			"st": "Buenos Aires",
			"countryCode": 32,
			"co": "Argentina",
			"c": "AR",
			"wWWHomePage": f"https://{f_runtime_settings.LDAP_DOMAIN}",
			"userPrincipalName": f"testuser@{f_runtime_settings.LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN}",
			"userAccountControl": 66048,
			"primaryGroupID": 513,
			"whenCreated": "fake_creation_date",
			"whenChanged": "fake_changed_date",
			"objectClass": ["top", "person", "organizationalPerson", "user"],
			"objectCategory": f"CN=Person,CN=Schema,CN=Configuration,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}",
			"objectSid": b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x11^\xb3\x83j\x06\x94\x00\x80\xdbi\xaaQ\x04\x00\x00",
			"objectRid": 1105,
			"lastLogon": "fake_logon_date",
			"badPwdCount": 0,
			"pwdLastSet": "fake_pwd_last_set",
			"sAMAccountType": 805306368,
			"memberOf": f"CN=Administrators,CN=Builtin,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}",
		}

	return maker


@pytest.fixture
def f_object_attrs_group(f_runtime_settings: RuntimeSettingsSingleton) -> dict:
	def maker():
		return {
			"name": "Test Group",
			"distinguishedName": f"cn=Test Group,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}",
			"type": "Group",
			"objectSid": b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x11^\xb3\x83j\x06\x94\x00\x80\xdbi\xaaR\x04\x00\x00",
			"objectRid": 1106,
			"objectCategory": f"CN=Group,CN=Schema,CN=Configuration,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}",
			"objectClass": ["top", "group"],
		}

	return maker


class FakeUserEntry:
	entry_dn: str = None
	entry_attributes: str = None
	name: str = None
	distinguishedName: str = None
	type: str = None
	givenName: str = None
	sn: str = None
	displayName: str = None
	sAMAccountName: str = None
	username: str = None
	mail: str = None
	telephoneNumber: str = None
	streetAddress: str = None
	postalCode: str = None
	l: str = None
	st: str = None
	countryCode: str = None
	co: str = None
	c: str = None
	wWWHomePage: str = None
	userPrincipalName: str = None
	userAccountControl: str = None
	primaryGroupID: str = None
	whenCreated: str = None
	whenChanged: str = None
	objectClass: list[str] = None
	objectCategory: str = None
	objectSid: bytes = None
	objectRid: str = None
	lastLogon: str = None
	sAMAccountType: str = None
	memberOf: list[str] = None
	pwdLastSet: int = None
	badPwdCount: int = None


@pytest.fixture
def f_object_entry_user(f_object_attrs_user, mocker: MockerFixture):
	def maker(attrs=None, **kwargs):
		if not attrs:
			attrs = {}
		m_attrs: dict = f_object_attrs_user() | attrs
		m_entry = mocker.Mock(spec=FakeUserEntry)
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
		m_entry.entry_dn = m_attrs["distinguishedName"]
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


@pytest.mark.parametrize(
	"auto_fetch",
	(
		True,
		False,
	),
	ids=lambda x: "With auto_fetch" if x else "Without auto_fetch",
)
def test_init(
	mocker: MockerFixture,
	f_connection,
	f_runtime_settings: RuntimeSettingsSingleton,
	auto_fetch,
	f_object_args,
):
	object_args = f_object_args()
	m_set_kwargs: MockType = mocker.patch.object(LDAPObject, "__set_kwargs__")
	m_fetch_object: MockType = mocker.patch.object(
		LDAPObject, "__fetch_object__"
	)
	m_ldap_object = LDAPObject(**object_args, auto_fetch=auto_fetch)
	object_args.pop("connection")
	assert m_ldap_object.entry == None
	assert m_ldap_object.attributes == None
	assert m_ldap_object.name == f_runtime_settings.LDAP_AUTH_SEARCH_BASE
	assert m_ldap_object.search_base == f_runtime_settings.LDAP_AUTH_SEARCH_BASE
	assert m_ldap_object.connection == f_connection
	assert (
		m_ldap_object.username_identifier
		== f_runtime_settings.LDAP_FIELD_MAP["username"]
	)
	assert m_ldap_object.excluded_attributes == []
	assert m_ldap_object.required_attributes == DEFAULT_REQUIRED_LDAP_ATTRS
	assert m_ldap_object.container_types == DEFAULT_CONTAINER_TYPES
	assert m_ldap_object.user_types == DEFAULT_USER_TYPES
	assert m_ldap_object.search_attrs == "+"
	assert (
		m_ldap_object.search_filter
		== f"(distinguishedName={object_args.get('dn')})"
	)
	m_set_kwargs.assert_called_once_with(object_args)
	if auto_fetch:
		m_fetch_object.assert_called_once()
	else:
		m_fetch_object.assert_not_called()


def test_dunder_set_kwargs(mocker: MockerFixture, f_connection, f_object_args):
	object_args = f_object_args()
	mocker.patch.object(LDAPObject, "__fetch_object__")
	m_ldap_object = LDAPObject(**object_args)
	c = m_ldap_object.search_attrs.count("distinguishedName")
	m_ldap_object.search_attrs.remove("distinguishedName")
	m_ldap_object.__set_kwargs__(
		{
			"a": 1,
			"b": 2,
		}
	)
	# Check if new kwargs were added as attributes
	assert getattr(m_ldap_object, "a") == 1
	assert getattr(m_ldap_object, "b") == 2

	# Check if required attribute was re-added to ldap_attrs list
	assert "distinguishedName" in m_ldap_object.search_attrs


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
def test_dunder_get__methods(mocker, get_name_args):
	cls_attribute = get_name_args[1] or get_name_args[0]
	cls_method = get_name_args[0]
	mocker.patch.object(LDAPObject, "__init__", return_value=None)
	m_ldap_object = LDAPObject()
	setattr(m_ldap_object, cls_attribute, cls_attribute)
	method = getattr(m_ldap_object, f"__get_{cls_method}__")
	assert method() == cls_attribute


def test_dunder_fetch_object_returns_none_on_empty_response(
	f_connection, f_object_args
):
	object_args = f_object_args()
	m_ldap_object = LDAPObject(**object_args)
	f_connection.entries = []
	f_connection.search.assert_called_once_with(
		search_base=m_ldap_object.search_base,
		search_filter=m_ldap_object.search_filter,
		search_scope="SUBTREE",
		attributes=m_ldap_object.search_attrs,
	)
	assert m_ldap_object.__fetch_object__() is None


@pytest.mark.parametrize(
	"test_entry",
	(
		"f_object_entry_user",
		"f_object_entry_group",
	),
)
def test_dunder_fetch_object(
	test_entry, request: FixtureRequest, f_connection, f_object_args
):
	m_entry = request.getfixturevalue(test_entry)()
	f_connection.entries = [m_entry]

	object_args = f_object_args()
	m_ldap_object = LDAPObject(**object_args)
	f_connection.search.assert_called_once_with(
		search_base=m_ldap_object.search_base,
		search_filter=m_ldap_object.search_filter,
		search_scope="SUBTREE",
		attributes=m_ldap_object.search_attrs,
	)
	m_ldap_object.__fetch_object__() == m_entry


def test_dunder_fetch_object_removes_empty_string(
	f_object_attrs_user,
	f_object_entry_user,
	f_connection,
	f_object_args,
):
	m_entry = f_object_entry_user(attrs={"objectRid": ""})
	result: dict = deepcopy(f_object_attrs_user())
	result.pop("objectRid")

	f_connection.entries = [m_entry]

	object_args = f_object_args()
	m_ldap_object = LDAPObject(**object_args)
	f_connection.search.assert_called_once_with(
		search_base=m_ldap_object.search_base,
		search_filter=m_ldap_object.search_filter,
		search_scope="SUBTREE",
		attributes=m_ldap_object.search_attrs,
	)
	m_ldap_object.__fetch_object__() == result


@pytest.mark.parametrize(
	"object_classes",
	(
		"builtinDomain",  # single value
		["builtinDomain", "someOtherValue"],  # iterable
	),
)
def test_dunder_fetch_object_marks_builtin(
	object_classes,
	f_object_entry_user,
	f_connection,
	f_object_args,
):
	m_entry: dict = f_object_entry_user(attrs={"objectClass": object_classes})
	f_connection.entries = [m_entry]

	object_args = f_object_args()
	m_ldap_object = LDAPObject(**object_args)
	f_connection.search.assert_called_once_with(
		search_base=m_ldap_object.search_base,
		search_filter=m_ldap_object.search_filter,
		search_scope="SUBTREE",
		attributes=m_ldap_object.search_attrs,
	)
	assert m_ldap_object.attributes["builtin"] is True


def test_dunder_fetch_object_successful_user_fetch(
	f_object_args,
	f_object_entry_user,
	f_object_attrs_user,
	f_connection,
):
	# Setup
	object_args = f_object_args()
	mock_entry = f_object_entry_user()
	expected_attrs: dict = f_object_attrs_user()
	expected_attrs.pop("memberOf")

	# Configure the connection fixture
	f_connection.entries = [mock_entry]

	# Instantiate LDAPObject
	ldap_obj = LDAPObject(auto_fetch=False, **object_args)
	ldap_obj.excluded_attributes = []
	ldap_obj.search_attrs.extend(
		[
			"badPwdCount",
			"objectSid",
			"objectRid",
		]
	)

	# Execute
	result = ldap_obj.__fetch_object__()

	# Assert
	assert set(result.keys()) == set(ldap_obj.attributes.keys())
	assert set(result.keys()) == set(expected_attrs.keys())
	assert ldap_obj.entry == mock_entry
	f_connection.search.assert_called_once_with(
		search_base=ldap_obj.search_base,
		search_filter=ldap_obj.search_filter,
		search_scope="SUBTREE",
		attributes=ldap_obj.search_attrs,
	)


def test_dunder_fetch_object_no_results_returns_none(
	f_object_args, f_connection
):
	# Setup
	object_args = f_object_args()
	f_connection.entries = []

	# Instantiate LDAPObject
	ldap_obj = LDAPObject(auto_fetch=False, **object_args)

	# Execute
	result = ldap_obj.__fetch_object__()

	# Assert
	assert result is None
	assert ldap_obj.attributes is None
	assert ldap_obj.entry is None


def test_dunder_fetch_object_handles_sid_conversion(
	mocker, f_object_args, f_object_entry_user, f_connection
):
	# Setup
	object_args = f_object_args()
	mock_entry = f_object_entry_user()
	f_connection.entries = [mock_entry]

	# Mock SID conversion
	mock_sid = mocker.MagicMock(spec=SID)
	mock_sid.__str__.return_value = (
		"S-1-5-21-123456789-1234567890-123456789-1105"
	)
	mocker.patch("core.models.ldap_object.SID", return_value=mock_sid)

	# Instantiate LDAPObject
	ldap_obj = LDAPObject(auto_fetch=False, **object_args)

	# Execute
	ldap_obj.__fetch_object__()

	# Assert SID was processed
	assert (
		ldap_obj.attributes["objectSid"]
		== "S-1-5-21-123456789-1234567890-123456789-1105"
	)
	assert ldap_obj.attributes["objectRid"] == 1105


def test_dunder_fetch_object_handles_iterable_attributes(
	f_object_args, f_object_entry_user, f_connection
):
	# Setup
	object_args = f_object_args()
	mock_entry = f_object_entry_user(
		attrs={"objectClass": ["value1", "value2"]}
	)

	# Add an iterable attribute
	f_connection.entries = [mock_entry]
	object_args["ldap_attrs"] = DEFAULT_REQUIRED_LDAP_ATTRS + ["objectClass"]

	# Instantiate LDAPObject
	ldap_obj = LDAPObject(auto_fetch=False, **object_args)

	# Execute
	ldap_obj.__fetch_object__()

	# Assert iterable attribute was handled correctly
	assert ldap_obj.attributes["objectClass"] == ["value1", "value2"]


def test_dunder_ldap_attrs_returns_attribute_keys(
	f_object_args, f_object_entry_user, f_connection
):
	# Setup
	object_args = f_object_args()
	mock_entry = f_object_entry_user()
	f_connection.entries = [mock_entry]

	# Instantiate and fetch object
	ldap_obj = LDAPObject(auto_fetch=False, **object_args)
	ldap_obj.__fetch_object__()

	# Execute
	result = ldap_obj.__ldap_attrs__()

	# Assert
	assert isinstance(result, list)
	assert all(attr in result for attr in ldap_obj.attributes.keys())


def test_dunder_ldap_attrs_returns_empty_list_when_no_attributes(
	f_object_args, f_connection
):
	# Setup
	object_args = f_object_args()

	# Instantiate without fetching
	ldap_obj = LDAPObject(auto_fetch=False, **object_args)

	# Execute
	result = ldap_obj.__ldap_attrs__()

	# Assert
	assert result == []


def test_dunder_get_common_name_extracts_cn_from_dn(
	f_object_args, f_connection
):
	# Setup
	object_args = f_object_args()
	test_dn = "CN=Test User,CN=Users,DC=example,DC=com"

	# Instantiate
	ldap_obj = LDAPObject(auto_fetch=False, **object_args)

	# Execute
	result = ldap_obj.__get_common_name__(test_dn)

	# Assert
	assert result == "Test User"


def test_dunder_get_common_name_handles_empty_string(
	f_object_args, f_connection
):
	# Setup
	object_args = f_object_args()
	ldap_obj = LDAPObject(auto_fetch=False, **object_args)

	# Execute
	result = ldap_obj.__get_common_name__("")

	# Assert
	assert result == ""


def test_dunder_get_common_name_handles_malformed_dn(
	f_object_args, f_connection
):
	# Setup
	object_args = f_object_args()
	ldap_obj = LDAPObject(auto_fetch=False, **object_args)

	# Execute with malformed DN
	result = ldap_obj.__get_common_name__("not,a,proper,dn")

	# Assert
	assert result == "not"


def test_dunder_mapped_attrs(f_object_entry_user, f_object_args, f_connection, f_runtime_settings):
	# Setup
	object_args = f_object_args()
	ldap_obj = LDAPObject(auto_fetch=False, **object_args)
	ldap_obj.connection.entries = [f_object_entry_user()]
	ldap_obj.__fetch_object__()

	result = ldap_obj.__mapped_attrs__()
	assert isinstance(result, dict)
	for _local_alias, _ldap_alias in f_runtime_settings.LDAP_FIELD_MAP.items():
		if not _local_alias in result:
			continue
		assert _ldap_alias in ldap_obj.attributes.keys()


def test_dunder_get_and_set_attrs(
	f_object_entry_user, f_object_args, f_connection
):
	# Setup
	object_args = f_object_args()
	ldap_obj = LDAPObject(auto_fetch=False, **object_args)
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
