########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType
################################################################################
from core.ldap.filter import LDAPFilter

@pytest.mark.parametrize(
	"test_filters, expected",
	(
		(
			LDAPFilter.and_(
				LDAPFilter.eq("sAMAccountName", "testuser"),
				LDAPFilter.eq("objectClass", "person")
			),
			"(&(sAMAccountName=testuser)(objectClass=person))"
		),
		(
			LDAPFilter.and_(
				LDAPFilter.eq("sAMAccountName", "testuser"),
				LDAPFilter.eq("objectClass", "person"),
				LDAPFilter.eq("objectClass", "user"),
			),
			"(&(sAMAccountName=testuser)(objectClass=person)(objectClass=user))"
		),
		(
			LDAPFilter.or_(
				LDAPFilter.eq("sAMAccountName", "testuser"),
				LDAPFilter.eq("objectClass", "person")
			),
			"(|(sAMAccountName=testuser)(objectClass=person))"
		),
		(
			LDAPFilter.or_(
				LDAPFilter.eq("sAMAccountName", "testuser"),
				LDAPFilter.eq("objectClass", "person"),
				LDAPFilter.eq("objectClass", "user"),
			),
			"(|(sAMAccountName=testuser)(objectClass=person)(objectClass=user))"
		),
		(
			LDAPFilter.or_(
				LDAPFilter.and_(
					LDAPFilter.eq("sAMAccountName", "testuser1"),
					LDAPFilter.eq("objectClass", "person"),
				),
				LDAPFilter.and_(
					LDAPFilter.eq("sAMAccountName", "testuser2"),
					LDAPFilter.eq("objectClass", "person"),
				),
			),
			"(|" + \
				"(&" + \
				"(sAMAccountName=testuser1)(objectClass=person)" + \
				")" + \
				"(&" + \
				"(sAMAccountName=testuser2)(objectClass=person)" + \
				")" + \
			")"
		),
	),
	ids=[
		"AND expression with 2 elements",
		"AND expression with 3 elements",
		"OR expression with 2 elements",
		"OR expression with 3 elements",
		"OR expression with 2 AND expressions",
	]
)
def test_filter(test_filters: LDAPFilter, expected: str):
	flt = test_filters
	assert flt.to_string() == expected
