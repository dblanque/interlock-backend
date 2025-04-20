########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType
################################################################################
from core.ldap.filter import (
	LDAPFilter,
	LDAPFilterType,
	encapsulate,
	is_encapsulated
)

@pytest.mark.parametrize(
	"test_value, expected",
	(
		(
			"(something)",
			True,
		),
		(
			"(something",
			False,
		),
		(
			"something)",
			False,
		),
		(
			"something",
			False,
		),
	),
)
def test_is_encapsulated(test_value, expected):
	assert is_encapsulated(test_value) == expected

def test_is_encapsulated_raises():
	with pytest.raises(TypeError):
		is_encapsulated(False)

@pytest.mark.parametrize(
	"value",
	(
		"something",
		"something)",
		"(something",
		"(something)",
	),
)
def test_encapsulate(value):
	assert encapsulate(value) == "(something)"

def test_ldap_filter_equality():
	assert LDAPFilter.eq(
		"mockAttribute",
		"mockValue"
	).to_string() == "(mockAttribute=mockValue)"

def test_ldap_filter_presence():
	assert LDAPFilter.has("mockAttribute").to_string() == "(mockAttribute=*)"

@pytest.mark.parametrize(
	"parts, expected",
	(
		(
			["mockValue"],
			"(mockAttribute=mockValue)",
		),
		(
			["","mockValue"],
			"(mockAttribute=*mockValue)",
		),
		(
			["mockValue",""],
			"(mockAttribute=mockValue*)",
		),
		(
			["","mockValue",""],
			"(mockAttribute=*mockValue*)",
		),
	),
)
def test_ldap_filter_substring(parts: list[str], expected: str):
	assert LDAPFilter.substr("mockAttribute", parts).to_string() == expected

def test_ldap_filter_greater_or_equal():
	assert LDAPFilter.ge("mockAttribute", 1).to_string() == "(mockAttribute>=1)"

def test_ldap_filter_less_or_equal():
	assert LDAPFilter.le("mockAttribute", 1).to_string() == "(mockAttribute<=1)"

def test_ldap_filter_approximate():
	assert LDAPFilter.approximate("mockAttribute", 1).to_string() == "(mockAttribute~=1)"

@pytest.mark.parametrize(
	"count",
	(
		2,
		3,
		4,
	),
)
def test_ldap_filter_and(count: int):
	r = range(1, count)
	expected = "".join([f"(mockAttribute{str(i)}=mockValue{str(i)})" for i in r])
	assert LDAPFilter.and_(
		*[LDAPFilter.eq(f"mockAttribute{str(i)}",f"mockValue{str(i)}") for i in r]
	).to_string() == f"(&{expected})"

@pytest.mark.parametrize(
	"count",
	(
		2,
		3,
		4,
	),
)
def test_ldap_filter_or(count: int):
	r = range(1, count)
	expected = "".join([f"(mockAttribute{str(i)}=mockValue{str(i)})" for i in r])
	assert LDAPFilter.or_(
		*[LDAPFilter.eq(f"mockAttribute{str(i)}",f"mockValue{str(i)}") for i in r]
	).to_string() == f"(|{expected})"

def test_ldap_filter_not():
	assert LDAPFilter.not_(
		LDAPFilter.eq("mockAttribute","mockValue")
	).to_string() == "(!(mockAttribute=mockValue))"

def test_parse_simple_filter():
	ldf = LDAPFilter.from_string("(mockAttribute=mockValue)")
	assert ldf.attribute == "mockAttribute"
	assert ldf.value == "mockValue"

def test_parse_simple_filter_presence():
	ldf = LDAPFilter.from_string("(mockAttribute=*)")
	assert ldf.type == LDAPFilterType.PRESENCE
	assert ldf.attribute == "mockAttribute"

@pytest.mark.parametrize(
	"operator",
	(
		LDAPFilterType.GREATER_OR_EQUAL,
		LDAPFilterType.LESS_OR_EQUAL,
		LDAPFilterType.APPROXIMATE,
	),
)
def test_parse_simple_filter_operator(operator: LDAPFilterType):
	ldf = LDAPFilter.from_string(f"(mockAttribute{operator.value}*)")
	assert ldf.type == operator
	assert ldf.attribute == "mockAttribute"

def test_parse_simple_filter_raises_invalid_format():
	with pytest.raises(ValueError, match="Invalid filter format"):
		LDAPFilter.from_string("(mockAttribute@=badformat)")

def test_parse_complex_filter_and():
	ldf = LDAPFilter.from_string("(&(mockAttribute1=mockValue1)(mockAttribute2=mockValue2))")
	assert ldf.type == LDAPFilterType.AND
	assert ldf.children[0].attribute == "mockAttribute1"
	assert ldf.children[0].value == "mockValue1"
	assert ldf.children[1].attribute == "mockAttribute2"
	assert ldf.children[1].value == "mockValue2"

def test_parse_complex_filter_not():
	ldf = LDAPFilter.from_string("(!(mockAttribute=mockValue))")
	assert ldf.type == LDAPFilterType.NOT
	assert ldf.children[0].type == LDAPFilterType.EQUALITY
	assert ldf.children[0].attribute == "mockAttribute"
	assert ldf.children[0].value == "mockValue"

def test_to_string():
	assert LDAPFilter.eq(
		attribute="mockAttribute",
		value="mockValue",
	).__str__() == "(mockAttribute=mockValue)"

def test_to_string_unsupported():
	with pytest.raises(ValueError, match="Unsupported filter type"):
		LDAPFilter(type="bad_type").to_string()

@pytest.mark.parametrize(
	"parts",
	(
		["part1", "part2", "part3"], # Wildcard between parts only
		["", "part1", "part2", "part3", ""], # Wildcard between parts, at end and at start
		["", "part1", "part2", "part3"], # Wildcard between parts, and at start
		["part1", "part2", "part3", ""], # Wildcard between parts, and at end
	),
	ids=[
		"Wildcard between parts only",
		"Wildcard between parts, at end, and at start",
		"Wildcard between parts, and at start",
		"Wildcard between parts, and at end",
	]
)
def test_parse_substring_filter(parts: list[str]):
	substr_search = "*".join(parts)
	ldf = LDAPFilter.from_string(f"(mockAttribute={substr_search})")
	assert ldf.parts == parts

def test_parse_nested_ldap_filter_or():
	ldf = LDAPFilter.from_string("(|(mockAttribute1=mockValue1)(&(mockAttribute2=mockValue2)(mockAttribute3=mockValue3)))")
	assert ldf.type == LDAPFilterType.OR
	assert ldf.children[0].attribute == "mockAttribute1"
	assert ldf.children[0].value == "mockValue1"
	assert ldf.children[1].children[0].attribute == "mockAttribute2"
	assert ldf.children[1].children[0].value == "mockValue2"
	assert ldf.children[1].children[1].attribute == "mockAttribute3"
	assert ldf.children[1].children[1].value == "mockValue3"

def test_from_string_raises_must_be_enclosed():
	with pytest.raises(ValueError, match="must be enclosed"):
		LDAPFilter.from_string("(mockAttribute=mockValue")

def test_from_string_raises_empty_filter():
	with pytest.raises(ValueError, match="Empty filter"):
		LDAPFilter.from_string("()")

def test_parse_next_filter_raises_component_must_start_with_parentheses():
	with pytest.raises(ValueError, match="must start with"):
		LDAPFilter.from_string("(&(mockAttribute1=mockValue1)mockAttribute2=mockValue2))")

def test_parse_next_filter_raises_unmatched_parentheses():
	with pytest.raises(ValueError, match="Unmatched parentheses"):
		LDAPFilter.from_string("(&(mockAttribute1=mockValue1)(mockAttribute2=mockValue2)")

def test_parse_complex_filter_raises_requires_a_child():
	with pytest.raises(ValueError, match="NOT filter requires a child"):
		LDAPFilter.from_string("(!)")

def test_parse_complex_filter_raises_unexpected_characters():
	with pytest.raises(ValueError, match="Unexpected characters after NOT filter"):
		LDAPFilter.from_string("(!(mockAttribute1=mockValue1)asd)")

@pytest.mark.parametrize("expr", (LDAPFilterType.AND, LDAPFilterType.OR),)
def test_parse_complex_filter_raises_requires_children(expr: LDAPFilterType):
	with pytest.raises(ValueError, match="filter requires children"):
		LDAPFilter.from_string(f"({expr.value})")

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
def test_filter_expressions(test_filters: LDAPFilter, expected: str):
	flt = test_filters
	assert flt.to_string() == expected
