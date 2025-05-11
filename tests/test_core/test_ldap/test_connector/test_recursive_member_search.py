########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType

################################################################################
from core.ldap.defaults import LDAP_AUTH_SEARCH_BASE
from core.ldap.connector import recursive_member_search


@pytest.fixture
def m_group_dn():
	return f"cn=group,{LDAP_AUTH_SEARCH_BASE}"


@pytest.fixture
def m_nested_group_dn():
	return f"cn=group_nested,{LDAP_AUTH_SEARCH_BASE}"


@pytest.mark.parametrize(
	"user_dn, group_dn",
	(
		([], "group_dn"),  # Bad type for user_dn
		("user_dn", []),  # Bad type for group_dn
	),
)
def test_recursive_member_search_type_errors(
	user_dn, group_dn, f_ldap_connection
):
	with pytest.raises(TypeError):
		recursive_member_search(user_dn, f_ldap_connection, group_dn)


@pytest.mark.parametrize(
	"user_dn, group_dn",
	(
		("", "group_dn"),  # Zero length user_dn
		("user_dn", ""),  # Zero length group_dn
	),
)
def test_recursive_member_search_len_errors(
	user_dn, group_dn, f_ldap_connection
):
	with pytest.raises(ValueError):
		recursive_member_search(user_dn, f_ldap_connection, group_dn)


def test_recursive_member_search_direct(
	# Fixtures
	f_ldap_connection,
	f_user_dn,
	m_group_dn,
	mocker: MockerFixture,
):
	m_entry = mocker.MagicMock()
	# Mock objectClass ldap attr
	m_object_classes = mocker.Mock()
	m_object_classes.values = ["group"]
	m_entry.objectClass = m_object_classes
	# mock member ldap attr
	m_member = mocker.Mock()
	m_member.values = [f_user_dn]
	m_entry.member = m_member
	f_ldap_connection.entries = [m_entry]
	assert (
		recursive_member_search(f_user_dn, f_ldap_connection, m_group_dn)
		is True
	)


def test_recursive_member_search_nested(
	# Fixtures
	f_ldap_connection,
	f_user_dn,
	m_group_dn,
	m_nested_group_dn,
	mocker: MockerFixture,
):
	# Mock Parent Entry
	m_entry = mocker.MagicMock()
	# Mock objectClass ldap attr
	m_object_classes = mocker.Mock()
	m_object_classes.values = ["group"]
	m_entry.objectClass = m_object_classes
	# mock member ldap attr
	m_member = mocker.Mock()
	m_member.values = [m_nested_group_dn]
	m_entry.member = m_member

	# Mock Nested Entry
	m_entry_nested = mocker.MagicMock()
	# Mock objectClass ldap attr
	m_entry_nested.objectClass = m_object_classes
	# mock member ldap attr
	m_member_nested = mocker.Mock()
	m_member_nested.values = [f_user_dn]
	m_entry_nested.member = m_member_nested

	f_ldap_connection.entries = [m_entry, m_entry_nested]
	assert (
		recursive_member_search(f_user_dn, f_ldap_connection, m_group_dn)
		is True
	)


def test_recursive_member_search_not_in_member(
	# Fixtures
	f_ldap_connection,
	f_user_dn,
	m_group_dn,
	mocker: MockerFixture,
):
	m_entry = mocker.MagicMock()
	# Mock objectClass ldap attr
	m_object_classes = mocker.Mock()
	m_object_classes.values = ["group"]
	m_entry.objectClass = m_object_classes
	# mock member ldap attr
	m_member = mocker.Mock()
	m_member.values = []
	m_entry.member = m_member
	f_ldap_connection.entries = [m_entry]
	assert (
		recursive_member_search(f_user_dn, f_ldap_connection, m_group_dn)
		is False
	)


def test_recursive_member_search_verify_filter(
	# Fixtures
	f_ldap_connection,
	f_user_dn,
	m_group_dn,
	mocker,
):
	m_entry = mocker.MagicMock()
	# Mock objectClass ldap attr
	m_object_classes = mocker.Mock()
	m_object_classes.values = ["group"]
	m_entry.objectClass = m_object_classes
	# mock member ldap attr
	m_member = mocker.Mock()
	m_member.values = []
	m_entry.member = m_member
	f_ldap_connection.entries = [m_entry]

	recursive_member_search(f_user_dn, f_ldap_connection, m_group_dn)

	expected_filter = f"(&(distinguishedName={m_group_dn})(objectClass=group))"
	f_ldap_connection.search.assert_called_with(
		LDAP_AUTH_SEARCH_BASE,
		expected_filter,
		attributes=["member", "objectClass", "distinguishedName"],
	)
