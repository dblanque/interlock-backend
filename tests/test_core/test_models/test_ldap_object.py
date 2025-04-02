import pytest
from pytest_mock import MockType
from core.models.ldap_object import (
	LDAPObject,
	LDAPObjectOptions,
	DEFAULT_EXCLUDED_LDAP_ATTRS,
	DEFAULT_REQUIRED_LDAP_ATTRS,
	DEFAULT_CONTAINER_TYPES,
	DEFAULT_USER_TYPES,
)

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
def test_init(mocker, f_connection, g_runtime_settings, auto_fetch):
	object_args: LDAPObjectOptions = {
		"connection": f_connection,
		"dn": f"cn=testobject,{g_runtime_settings.LDAP_AUTH_SEARCH_BASE}",
	}
	m_reset_kwargs: MockType = mocker.patch.object(LDAPObject, LDAPObject.__set_kwargs__.__name__)
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
	assert m_ldap_object.ldap_attrs == g_runtime_settings.LDAP_DIRTREE_ATTRIBUTES
	assert m_ldap_object.ldap_filter == f"(distinguishedName={object_args.get('dn')})"
	m_reset_kwargs.assert_called_once_with(object_args)
	if auto_fetch:
		m_fetch_object.assert_called_once()
	else:
		m_fetch_object.assert_not_called()

def test_dunder_reset_kwargs(mocker, f_connection, g_runtime_settings):
	object_args: LDAPObjectOptions = {
		"connection": f_connection,
		"dn": f"cn=testobject,{g_runtime_settings.LDAP_AUTH_SEARCH_BASE}",
	}
	m_fetch_object: MockType = mocker.patch.object(LDAPObject, "__fetch_object__")
	m_ldap_object = LDAPObject(**object_args)
	m_ldap_object.__set_kwargs__({
		"a": 1,
		"b": 2,
		"c": 3
	})
	assert getattr(m_ldap_object, "a") == 1
	assert getattr(m_ldap_object, "b") == 2
	assert getattr(m_ldap_object, "c") == 3

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
		mocker,
		f_connection,
		g_runtime_settings,
	):
	object_args: LDAPObjectOptions = {
		"connection": f_connection,
		"dn": f"cn=testobject,{g_runtime_settings.LDAP_AUTH_SEARCH_BASE}",
	}
	m_ldap_object = LDAPObject(**object_args)
	f_connection.search.assert_called_once_with(
		search_base=m_ldap_object.search_base,
		search_filter=m_ldap_object.ldap_filter,
		search_scope="SUBTREE",
		attributes=m_ldap_object.ldap_attrs,
	)
	assert m_ldap_object.__fetch_object__() is None
