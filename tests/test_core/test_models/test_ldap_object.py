import pytest
from pytest_mock import MockType
from unittest.mock import Mock
from core.ldap.security_identifier import SID
from core.models.ldap_object import (
	LDAPObject,
	LDAPObjectOptions,
	DEFAULT_EXCLUDED_LDAP_ATTRS,
	DEFAULT_REQUIRED_LDAP_ATTRS,
	DEFAULT_CONTAINER_TYPES,
	DEFAULT_USER_TYPES,
)
from copy import deepcopy

@pytest.fixture
def f_object_args(f_connection, g_runtime_settings) -> LDAPObjectOptions:
	def maker(**kwargs):
		return {
			"connection": f_connection,
			"dn": f"cn=testobject,{g_runtime_settings.LDAP_AUTH_SEARCH_BASE}",
			**kwargs
		}
	return maker

@pytest.fixture
def f_object_attrs_user(g_runtime_settings) -> dict:
	def maker():
		return {
			'name': 'Test User',
			'distinguishedName': f'CN=Test User,OU=Administrators,{g_runtime_settings.LDAP_AUTH_SEARCH_BASE}',
			'type': 'Person',
			'givenName': 'Test',
			'sn': 'User',
			'displayName': 'Test User',
			'sAMAccountName': 'testuser',
			'username': 'testuser',
			'mail': f'testuser@{g_runtime_settings.LDAP_DOMAIN}',
			'telephoneNumber': '+5491112345678',
			'streetAddress': 'Street Address Example',
			'postalCode': 'POSTALCODE',
			'l': 'Some Town',
			'st': 'Buenos Aires',
			'countryCode': '32',
			'co': 'Argentina',
			'c': 'AR',
			'wWWHomePage': f'https://{g_runtime_settings.LDAP_DOMAIN}',
			'userPrincipalName': f'testuser@{g_runtime_settings.LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN}',
			'userAccountControl': '66048',
			'primaryGroupID': '513',
			'whenCreated': "fake_creation_date",
			'whenChanged': "fake_changed_date",
			'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
			'objectCategory': f'CN=Person,CN=Schema,CN=Configuration,{g_runtime_settings.LDAP_AUTH_SEARCH_BASE}',
			'objectSid': b'\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x11^\xb3\x83j\x06\x94\x00\x80\xdbi\xaaQ\x04\x00\x00',
			'objectRid': '1105',
			'lastLogon': "fake_logon_date",
			'badPwdCount': '0',
			'pwdLastSet': 'fake_pwd_last_set',
			'sAMAccountType': '805306368',
			'memberOf': [f'CN=Administrators,CN=Builtin,{g_runtime_settings.LDAP_AUTH_SEARCH_BASE}']
		}
	return maker

@pytest.fixture
def f_object_attrs_group(g_runtime_settings) -> dict:
	def maker():
		return {
			'name': 'Test Group',
			'distinguishedName': f"cn=Test Group,{g_runtime_settings.LDAP_AUTH_SEARCH_BASE}",
			'type': 'Group',
			'objectSid': b'\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x11^\xb3\x83j\x06\x94\x00\x80\xdbi\xaaR\x04\x00\x00',
			'objectRid': '1106',
			'objectCategory': [f'CN=Group,CN=Schema,CN=Configuration,{g_runtime_settings.LDAP_AUTH_SEARCH_BASE}'],
			'objectClass': ['top', 'group']
		}
	return maker

class FakeUserEntry:
	name: str
	distinguishedName: str
	type: str
	givenName: str
	sn: str
	displayName: str
	sAMAccountName: str
	username: str
	mail: str
	telephoneNumber: str
	streetAddress: str
	postalCode: str
	l: str
	st: str
	countryCode: str
	co: str
	c: str
	wWWHomePage: str
	userPrincipalName: str
	userAccountControl: str
	primaryGroupID: str
	whenCreated: str
	whenChanged: str
	objectClass: list[str]
	objectCategory: str
	objectSid: bytes
	objectRid: str
	lastLogon: str
	sAMAccountType: str
	memberOf: list[str]

@pytest.fixture
def f_object_entry_user(f_object_attrs_user, mocker):
	def maker():
		m_attrs: dict = f_object_attrs_user()
		m_entry = mocker.Mock(spec=FakeUserEntry)
		for attr, val in m_attrs.items():
			setattr(m_entry, attr, val)
		return m_entry
	return maker

@pytest.fixture
def f_object_entry_group(f_object_attrs_group, mocker):
	def maker():
		m_attrs: dict = f_object_attrs_group()
		m_entry = mocker.Mock()
		for attr, val in m_attrs.items():
			setattr(m_entry, attr, val)
		return m_entry
	return maker

@pytest.mark.parametrize(
	"object_args, expected_exc_msg_match",
	(
		(
			{},
			"requires an LDAP Connection"
		),
		(
			{
				"connection": "something"
			},
			"requires a Distinguished Name"
		),
	),
	ids=[
		"No LDAP Connection kwarg raises Exception",
		"No Distinguished Name kwarg raises Exception",
	]
)
def test_init_raises_kwarg_exception(
		object_args, expected_exc_msg_match):
	with pytest.raises(Exception, match=expected_exc_msg_match):
		LDAPObject(**object_args)

@pytest.mark.parametrize(
	"auto_fetch",
	(
		True,
		False,
	),
	ids=lambda x: "With auto_fetch" if x else "Without auto_fetch"
)
def test_init(mocker, f_connection, g_runtime_settings, auto_fetch, f_object_args):
	object_args: LDAPObjectOptions = f_object_args()
	m_set_kwargs: MockType = mocker.patch.object(LDAPObject, LDAPObject.__set_kwargs__.__name__)
	m_fetch_object: MockType = mocker.patch.object(LDAPObject, LDAPObject.__fetch_object__.__name__)
	m_ldap_object = LDAPObject(**object_args, auto_fetch=auto_fetch)
	object_args.pop("connection")
	assert m_ldap_object.entry == None
	assert m_ldap_object.attributes == None
	assert m_ldap_object.name == g_runtime_settings.LDAP_AUTH_SEARCH_BASE
	assert m_ldap_object.search_base == g_runtime_settings.LDAP_AUTH_SEARCH_BASE
	assert m_ldap_object.connection == f_connection
	assert m_ldap_object.username_identifier == g_runtime_settings.LDAP_AUTH_USER_FIELDS["username"]
	assert m_ldap_object.excluded_ldap_attrs == DEFAULT_EXCLUDED_LDAP_ATTRS
	assert m_ldap_object.required_ldap_attrs == DEFAULT_REQUIRED_LDAP_ATTRS
	assert m_ldap_object.container_types == DEFAULT_CONTAINER_TYPES
	assert m_ldap_object.user_types == DEFAULT_USER_TYPES
	assert m_ldap_object.recursive is False
	assert m_ldap_object.test_fetch is False
	dirtree_attrs = g_runtime_settings.LDAP_DIRTREE_ATTRIBUTES + [
		g_runtime_settings.LDAP_AUTH_USER_FIELDS["username"],
		"username",
	]
	assert m_ldap_object.ldap_attrs == list(set(dirtree_attrs))
	assert m_ldap_object.ldap_filter == f"(distinguishedName={object_args.get('dn')})"
	m_set_kwargs.assert_called_once_with(object_args)
	if auto_fetch:
		m_fetch_object.assert_called_once()
	else:
		m_fetch_object.assert_not_called()

def test_dunder_set_kwargs(mocker, f_connection, g_runtime_settings, f_object_args):
	object_args: LDAPObjectOptions = f_object_args()
	mocker.patch.object(LDAPObject, LDAPObject.__fetch_object__.__name__)
	m_ldap_object = LDAPObject(**object_args)
	c = m_ldap_object.ldap_attrs.count("distinguishedName")
	m_ldap_object.ldap_attrs.remove("distinguishedName")
	m_ldap_object.__set_kwargs__({
		"a": 1,
		"b": 2,
	})
	# Check if new kwargs were added as attributes
	assert getattr(m_ldap_object, "a") == 1
	assert getattr(m_ldap_object, "b") == 2

	# Check if required attribute was re-added to ldap_attrs list
	assert "distinguishedName" in m_ldap_object.ldap_attrs


@pytest.mark.parametrize(
	"get_name_args",
	(
		("connection", None,),
		("entry", None,),
		("object", "attributes",),
	),
	ids=[
		"__get_connection__ returns connection",
		"__get_entry__ returns entry",
		"__get_object__ returns attributes",
	]
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
		f_connection, g_runtime_settings, f_object_args):
	object_args: LDAPObjectOptions = f_object_args()
	m_ldap_object = LDAPObject(**object_args)
	f_connection.search.assert_called_once_with(
		search_base=m_ldap_object.search_base,
		search_filter=m_ldap_object.ldap_filter,
		search_scope="SUBTREE",
		attributes=m_ldap_object.ldap_attrs,
	)
	assert m_ldap_object.__fetch_object__() is None

@pytest.mark.parametrize(
	"test_entry",
	(
		"f_object_entry_user",
		"f_object_entry_group",
	),
)
def test_dunder_fetch_object(test_entry, request, f_connection, g_runtime_settings, f_object_args):
	m_entry = request.getfixturevalue(test_entry)()
	f_connection.entries = [m_entry]

	object_args: LDAPObjectOptions = f_object_args()
	m_ldap_object = LDAPObject(**object_args)
	f_connection.search.assert_called_once_with(
		search_base=m_ldap_object.search_base,
		search_filter=m_ldap_object.ldap_filter,
		search_scope="SUBTREE",
		attributes=m_ldap_object.ldap_attrs,
	)
	m_ldap_object.__fetch_object__() == m_entry

def test_dunder_fetch_object_removes_empty_list_string(f_object_attrs_user, f_object_entry_user, f_connection, g_runtime_settings, f_object_args):
	m_entry = f_object_entry_user()
	m_entry.objectRid = "[]"
	result: dict = deepcopy(f_object_attrs_user())
	result.pop("objectRid")

	f_connection.entries = [m_entry]

	object_args: LDAPObjectOptions = f_object_args()
	m_ldap_object = LDAPObject(**object_args)
	f_connection.search.assert_called_once_with(
		search_base=m_ldap_object.search_base,
		search_filter=m_ldap_object.ldap_filter,
		search_scope="SUBTREE",
		attributes=m_ldap_object.ldap_attrs,
	)
	m_ldap_object.__fetch_object__() == result

def test_dunder_fetch_object_marks_builtin(f_object_entry_user, f_connection, g_runtime_settings, f_object_args):
	m_entry: dict = f_object_entry_user()
	m_entry.objectClass.append("builtinDomain")
	f_connection.entries = [m_entry]

	object_args: LDAPObjectOptions = f_object_args()
	m_ldap_object = LDAPObject(**object_args)
	f_connection.search.assert_called_once_with(
		search_base=m_ldap_object.search_base,
		search_filter=m_ldap_object.ldap_filter,
		search_scope="SUBTREE",
		attributes=m_ldap_object.ldap_attrs,
	)
	assert m_ldap_object.attributes["builtin"] is True

def test_dunder_fetch_object_successful_user_fetch(
	f_object_args, 
	f_object_entry_user,
	f_object_attrs_user,
	f_connection,
	g_runtime_settings,
):
	# Setup
	object_args: LDAPObjectOptions = f_object_args()
	mock_entry = f_object_entry_user()
	expected_attrs = f_object_attrs_user()
	expected_attrs.pop("memberOf")

	# Configure the connection fixture
	f_connection.entries = [mock_entry]
	
	# Instantiate LDAPObject
	ldap_obj = LDAPObject(auto_fetch=False, **object_args)
	
	# Execute
	result = ldap_obj.__fetch_object__()
	
	# Assert
	assert result == ldap_obj.attributes
	assert set(result) == set(expected_attrs)
	assert ldap_obj.entry == mock_entry
	f_connection.search.assert_called_once_with(
		search_base=ldap_obj.search_base,
		search_filter=ldap_obj.ldap_filter,
		search_scope="SUBTREE",
		attributes=ldap_obj.ldap_attrs
	)

def test_dunder_fetch_object_no_results_returns_none(f_object_args, f_connection):
	# Setup
	object_args: LDAPObjectOptions = f_object_args()
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
	mocker, 
	f_object_args, 
	f_object_entry_user,
	f_connection
):
	# Setup
	object_args: LDAPObjectOptions = f_object_args()
	mock_entry = f_object_entry_user()
	f_connection.entries = [mock_entry]
	
	# Mock SID conversion
	mock_sid = mocker.MagicMock(spec=SID)
	mock_sid.__str__.return_value = "S-1-5-21-123456789-1234567890-123456789-1105"
	mocker.patch('core.models.ldap_object.SID', return_value=mock_sid)
	
	# Instantiate LDAPObject
	ldap_obj = LDAPObject(auto_fetch=False, **object_args)
	
	# Execute
	ldap_obj.__fetch_object__()
	
	# Assert SID was processed
	assert ldap_obj.attributes["objectSid"] == "S-1-5-21-123456789-1234567890-123456789-1105"
	assert ldap_obj.attributes["objectRid"] == "1105"

def test_dunder_fetch_object_handles_iterable_attributes(
	f_object_args,
	f_object_entry_user,
	f_connection
):
	# Setup
	object_args: LDAPObjectOptions = f_object_args()
	mock_entry = f_object_entry_user()
	
	# Add an iterable attribute
	mock_entry.someMultiValue = ["value1", "value2"]
	f_connection.entries = [mock_entry]
	object_args["ldap_attrs"] = DEFAULT_REQUIRED_LDAP_ATTRS + ["someMultiValue"]
	
	# Instantiate LDAPObject
	ldap_obj = LDAPObject(auto_fetch=False, **object_args)
	
	# Execute
	ldap_obj.__fetch_object__()
	
	# Assert iterable attribute was handled correctly
	assert ldap_obj.attributes["someMultiValue"] == ["value1", "value2"]

def test_dunder_fetch_object_handles_builtin_objects(
	f_object_args,
	f_object_entry_user,
	f_connection
):
	# Setup
	object_args: LDAPObjectOptions = f_object_args()
	mock_entry = f_object_entry_user()
	mock_entry.objectClass = ["top", "builtinDomain"]
	f_connection.entries = [mock_entry]
	
	# Instantiate LDAPObject
	ldap_obj = LDAPObject(auto_fetch=False, **object_args)
	
	# Execute
	ldap_obj.__fetch_object__()
	
	# Assert builtin flag was set
	assert ldap_obj.attributes["builtin"] is True

def test_dunder_ldap_attrs_returns_attribute_keys(
	f_object_args,
	f_object_entry_user,
	f_connection
):
	# Setup
	object_args: LDAPObjectOptions = f_object_args()
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
	f_object_args,
	f_connection
):
	# Setup
	object_args: LDAPObjectOptions = f_object_args()
	
	# Instantiate without fetching
	ldap_obj = LDAPObject(auto_fetch=False, **object_args)

	# Execute
	result = ldap_obj.__ldap_attrs__()
	
	# Assert
	assert result == []

def test_dunder_get_common_name_extracts_cn_from_dn(
	f_object_args,
	f_connection
):
	# Setup
	object_args: LDAPObjectOptions = f_object_args()
	test_dn = "CN=Test User,OU=Users,DC=example,DC=com"
	
	# Instantiate
	ldap_obj = LDAPObject(auto_fetch=False, **object_args)
	
	# Execute
	result = ldap_obj.__get_common_name__(test_dn)
	
	# Assert
	assert result == "Test User"

def test_dunder_get_common_name_handles_empty_string(
	f_object_args,
	f_connection
):
	# Setup
	object_args: LDAPObjectOptions = f_object_args()
	ldap_obj = LDAPObject(auto_fetch=False, **object_args)
	
	# Execute
	result = ldap_obj.__get_common_name__("")
	
	# Assert
	assert result == ""

def test_dunder_get_common_name_handles_malformed_dn(
	f_object_args,
	f_connection
):
	# Setup
	object_args: LDAPObjectOptions = f_object_args()
	ldap_obj = LDAPObject(auto_fetch=False, **object_args)
	
	# Execute with malformed DN
	result = ldap_obj.__get_common_name__("not,a,proper,dn")
	
	# Assert
	assert result == "not"