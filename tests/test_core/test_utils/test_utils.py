########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture
################################################################################
from ldap3 import Entry as LDAPEntry, Attribute as LDAPAttribute
from core.utils.main import (
	getlocalkeyforldapattr,
	getldapattrvalue,
	uppercase_ldif_identifiers,
)
from core.ldap.defaults import LDAP_LDIF_IDENTIFIERS
from core.constants.attrs import *


class TestGetLocalAliasForLDAPKey:
	@staticmethod
	@pytest.mark.parametrize(
		"local_alias, ldap_alias",
		(
			(
				LOCAL_ATTR_DN,
				LDAP_ATTR_DN,
			),
			(
				LOCAL_ATTR_USERNAME,
				LDAP_ATTR_USERNAME_SAMBA_ADDS,
			),
			(
				LOCAL_ATTR_EMAIL,
				LDAP_ATTR_EMAIL,
			),
			(
				LOCAL_ATTR_PASSWORD,
				LDAP_ATTR_PASSWORD,
			),
			(
				LOCAL_ATTR_FIRST_NAME,
				LDAP_ATTR_FIRST_NAME,
			),
			(
				LOCAL_ATTR_LAST_NAME,
				LDAP_ATTR_LAST_NAME,
			),
			(
				LOCAL_ATTR_FULL_NAME,
				LDAP_ATTR_FULL_NAME,
			),
			(
				LOCAL_ATTR_INITIALS,
				LDAP_ATTR_INITIALS,
			),
			(
				LOCAL_ATTR_PHONE,
				LDAP_ATTR_PHONE,
			),
			(
				LOCAL_ATTR_ADDRESS,
				LDAP_ATTR_ADDRESS,
			),
			(
				LOCAL_ATTR_POSTAL_CODE,
				LDAP_ATTR_POSTAL_CODE,
			),
			(
				LOCAL_ATTR_CITY,
				LDAP_ATTR_CITY,
			),
			(
				LOCAL_ATTR_STATE,
				LDAP_ATTR_STATE,
			),
			(
				LOCAL_ATTR_COUNTRY,
				LDAP_ATTR_COUNTRY,
			),
			(
				LOCAL_ATTR_COUNTRY_DCC,
				LDAP_ATTR_COUNTRY_DCC,
			),
			(
				LOCAL_ATTR_COUNTRY_ISO,
				LDAP_ATTR_COUNTRY_ISO,
			),
			(
				LOCAL_ATTR_WEBSITE,
				LDAP_ATTR_WEBSITE,
			),
			(
				LOCAL_ATTR_UPN,
				LDAP_ATTR_UPN,
			),
			(
				LOCAL_ATTR_UAC,
				LDAP_ATTR_UAC,
			),
			(
				LOCAL_ATTR_CREATED,
				LDAP_ATTR_CREATED,
			),
			(
				LOCAL_ATTR_MODIFIED,
				LDAP_ATTR_MODIFIED,
			),
			(
				LOCAL_ATTR_LAST_LOGIN_WIN32,
				LDAP_ATTR_LAST_LOGIN,
			),
			(
				LOCAL_ATTR_BAD_PWD_COUNT,
				LDAP_ATTR_BAD_PWD_COUNT,
			),
			(
				LOCAL_ATTR_PWD_SET_AT,
				LDAP_ATTR_PWD_SET_AT,
			),
			(
				LOCAL_ATTR_PRIMARY_GROUP_ID,
				LDAP_ATTR_PRIMARY_GROUP_ID,
			),
			(
				LOCAL_ATTR_OBJECT_CLASS,
				LDAP_ATTR_OBJECT_CLASS,
			),
			(
				LOCAL_ATTR_OBJECT_CATEGORY,
				LDAP_ATTR_OBJECT_CATEGORY,
			),
			(
				LOCAL_ATTR_RELATIVE_ID,
				LDAP_ATTR_RELATIVE_ID,
			),
			(
				LOCAL_ATTR_SECURITY_ID,
				LDAP_ATTR_SECURITY_ID,
			),
			(
				LOCAL_ATTR_ACCOUNT_TYPE,
				LDAP_ATTR_ACCOUNT_TYPE,
			),
			(
				LOCAL_ATTR_USER_GROUPS,
				LDAP_ATTR_USER_GROUPS,
			),
			(
				LOCAL_ATTR_GROUP_MEMBERS,
				LDAP_ATTR_GROUP_MEMBERS,
			),
			(
				LOCAL_ATTR_LOGON_TIMESTAMP,
				LDAP_ATTR_LOGON_TIMESTAMP,
			),
			(
				LOCAL_ATTR_EXPIRES_AT,
				LDAP_ATTR_EXPIRES_AT,
			),
			(
				LOCAL_ATTR_NAME,
				LDAP_ATTR_COMMON_NAME,
			),
			(
				LOCAL_ATTR_GROUP_TYPE,
				LDAP_ATTR_GROUP_TYPE,
			),
		),
	)
	def test_success(
		local_alias: str,
		ldap_alias: str,
	):
		assert getlocalkeyforldapattr(ldap_alias) == local_alias

	@staticmethod
	def test_raises_value_error():
		with pytest.raises(ValueError):
			getlocalkeyforldapattr("some_bad_key")

	@staticmethod
	def test_returns_args_default():
		assert (
			getlocalkeyforldapattr("some_bad_key", "mock_default")
			== "mock_default"
		)

	@staticmethod
	def test_returns_kwargs_default():
		assert (
			getlocalkeyforldapattr("some_bad_key", default="mock_default")
			== "mock_default"
		)

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


class TestGetLdapAttrValue:
	@staticmethod
	def test_get_existing_single_value_attribute(f_ldap_entry):
		assert getldapattrvalue(f_ldap_entry, "single_attr") == "mock_value"

	@staticmethod
	def test_get_existing_multi_value_attribute(f_ldap_entry):
		assert getldapattrvalue(f_ldap_entry, "multi_attr") == ["a", "b"]

	@staticmethod
	def test_get_non_existing_attribute_with_default(f_ldap_entry):
		result = getldapattrvalue(
			f_ldap_entry, "non_existing", default="default_value"
		)
		assert result == "default_value"

	@staticmethod
	def test_get_non_existing_attribute_with_args_default(f_ldap_entry):
		result = getldapattrvalue(f_ldap_entry, "non_existing", "args_default")
		assert result == "args_default"

	@staticmethod
	def test_get_non_existing_attribute_no_default(f_ldap_entry):
		with pytest.raises(AttributeError, match="has no attribute"):
			getldapattrvalue(f_ldap_entry, "non_existing")


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
