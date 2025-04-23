########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture
from ldap3 import Entry as LDAPEntry, Attribute as LDAPAttribute
from core.views.mixins.utils import (
	getldapattr,
	net_port_test,
	recursive_dict_find,
	uppercase_ldif_identifiers,
	is_non_str_iterable
)
from core.ldap.defaults import LDAP_LDIF_IDENTIFIERS
import socket

@pytest.fixture
def f_socket(mocker: MockerFixture):
	yield mocker.patch("socket.socket")

@pytest.fixture
def f_ldap_entry(mocker: MockerFixture) -> LDAPEntry:
    m_entry = mocker.MagicMock(spec=LDAPEntry)

    single_attr = mocker.Mock(spec=LDAPAttribute)
    single_attr.value = "mock_value"
    single_attr.values = ["mock_value"]

    multi_attr = mocker.Mock(spec=LDAPAttribute)
    multi_attr.value = ["a", "b"]
    multi_attr.values = ["a", "b"]

    m_entry.single_attr = single_attr
    m_entry.multi_attr = multi_attr

    return m_entry

class TestGetLdapAttr:
    @staticmethod
    def test_get_existing_single_value_attribute(f_ldap_entry):
        assert getldapattr(f_ldap_entry, "single_attr") == "mock_value"

    @staticmethod
    def test_get_existing_multi_value_attribute(f_ldap_entry):
        assert getldapattr(f_ldap_entry, "multi_attr") == ["a", "b"]

    @staticmethod
    def test_get_non_existing_attribute_with_default(f_ldap_entry):
        result = getldapattr(f_ldap_entry, "non_existing", default="default_value")
        assert result == "default_value"

    @staticmethod
    def test_get_non_existing_attribute_with_args_default(f_ldap_entry):
        result = getldapattr(f_ldap_entry, "non_existing", "args_default")
        assert result == "args_default"

    @staticmethod
    def test_get_non_existing_attribute_no_default(f_ldap_entry):
        with pytest.raises(AttributeError, match="has no attribute"):
            getldapattr(f_ldap_entry, "non_existing")

class TestNetPortTest:
	@staticmethod
	def test_successful_connection(f_socket):
		mock_instance = f_socket.return_value
		mock_instance.connect.return_value = None
		
		result = net_port_test("127.0.0.1", 389)
		assert result is True
		mock_instance.connect.assert_called_once_with(("127.0.0.1", 389))
		mock_instance.settimeout.assert_any_call(5)
		mock_instance.settimeout.assert_any_call(None)
		mock_instance.shutdown.assert_called_once_with(2)

	@staticmethod
	def test_failed_connection(f_socket):
		mock_instance = f_socket.return_value
		mock_instance.connect.side_effect = socket.error
		
		result = net_port_test("127.0.0.1", 389)
		assert result is False


class TestRecursiveDictFind:
	@staticmethod
	def test_find_top_level_key():
		test_dict = {"a": 1, "b": 2, "c": 3}
		assert recursive_dict_find(test_dict, "b") == 2

	@staticmethod
	def test_find_nested_key():
		test_dict = {
			"a": 1,
			"b": {
				"c": 2,
				"d": {
					"e": 3
				}
			}
		}
		assert recursive_dict_find(test_dict, "e") == 3

	def test_key_not_found(self):
		test_dict = {"a": 1, "b": 2}
		assert recursive_dict_find(test_dict, "c") is None

	def test_empty_dict(self):
		assert recursive_dict_find({}, "a") is None


class TestUppercaseLdifIdentifiers:
	@staticmethod
	def test_uppercase_identifiers():
		test_string = "cn=test,dc=example,dc=com"
		expected = "CN=test,DC=example,DC=com"
		
		# Get the actual identifiers from LDAP_LDIF_IDENTIFIERS
		identifiers = LDAP_LDIF_IDENTIFIERS
		for ident in identifiers:
			test_string = test_string.replace(f"{ident.upper()}=", f"{ident}=")
		
		result = uppercase_ldif_identifiers(test_string)
		assert result == expected

	def test_non_string_input(self):
		with pytest.raises(TypeError, match="Value must be str."):
			uppercase_ldif_identifiers(123)


class TestIsNonStrIterable:
	@staticmethod
	@pytest.mark.parametrize("value,expected", [
		([1, 2, 3], True),
		({"a": 1}, True),
		((1, 2), True),
		({1, 2}, True),
		("string", False),
		(123, False),
		(True, False),
		(None, False)
	])
	def test_various_types(value, expected):
		assert is_non_str_iterable(value) == expected