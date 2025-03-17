import pytest
from interlock_backend.ldap.adsi import (
	search_filter_add,
	LDAP_FILTER_AND,
	LDAP_FILTER_OR
)

@pytest.mark.parametrize(
	"filter_string,filter_add,operator,negate,expected",
	(
		(
			"objectClass=person",
			"sAMAccountName=testuser",
			LDAP_FILTER_AND,
			False,
			f"({LDAP_FILTER_AND}(objectClass=person)(sAMAccountName=testuser))"
		),
		(
			"objectClass=person",
			"sAMAccountName=testuser",
			LDAP_FILTER_OR,
			False,
			f"({LDAP_FILTER_OR}(objectClass=person)(sAMAccountName=testuser))"
		),
		(
			"objectClass=person",
			"sAMAccountName=testuser",
			LDAP_FILTER_AND,
			True,
			f"({LDAP_FILTER_AND}(objectClass=person)(!(sAMAccountName=testuser)))"
		),
		(
			"(objectClass=person)",
			"sAMAccountName=testuser",
			LDAP_FILTER_AND,
			False,
			f"({LDAP_FILTER_AND}(objectClass=person)(sAMAccountName=testuser))"
		),
		(
			"(objectClass=person)",
			"sAMAccountName=testuser",
			"and",
			False,
			f"({LDAP_FILTER_AND}(objectClass=person)(sAMAccountName=testuser))"
		),
		(
			"(objectClass=person)",
			"sAMAccountName=testuser",
			"or",
			False,
			f"({LDAP_FILTER_OR}(objectClass=person)(sAMAccountName=testuser))"
		),
		(
			"",
			"sAMAccountName=testuser",
			LDAP_FILTER_AND,
			False,
			f"(sAMAccountName=testuser)"
		),
	)
)
def test_search_filter_add(filter_string,filter_add,operator,negate,expected):
	assert search_filter_add(filter_string,filter_add,operator,negate) == expected

def test_search_filter_add_raises_empty_string():
	with pytest.raises(ValueError):
		search_filter_add("", "",LDAP_FILTER_AND)

def test_search_filter_add_raises_invalid_operator():
	with pytest.raises(ValueError):
		search_filter_add("", "objectClass=person","A")
