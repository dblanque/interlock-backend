########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType
################################################################################
from core.ldap.adsi import join_ldap_filter
from core.views.mixins.ldap.organizational_unit import (
	OrganizationalUnitMixin,
	LDAP_DEFAULT_DIRTREE_FILTER
)
from rest_framework.exceptions import ValidationError

@pytest.fixture
def f_ou_mixin(mocker: MockerFixture):
	m_mixin = OrganizationalUnitMixin()
	m_mixin.ldap_connection = mocker.MagicMock()
	return m_mixin

@pytest.fixture
def f_object_category_filter():
	def maker(**kwargs):
		flt = None
		for value in LDAP_DEFAULT_DIRTREE_FILTER["include"]["objectCategory"]:
			if value in kwargs:
				continue
			flt = join_ldap_filter(
				filter_string=flt,
				filter_to_add=f"objectCategory={value}",
				expression="|"
			)
		return flt
	return maker

@pytest.fixture
def f_object_class_filter():
	def maker(**kwargs):
		flt = None
		for value in LDAP_DEFAULT_DIRTREE_FILTER["include"]["objectClass"]:
			if value in kwargs:
				continue
			flt = join_ldap_filter(
				filter_string=flt,
				filter_to_add=f"objectClass={value}",
				expression="|"
			)
		return flt
	return maker

@pytest.fixture
def f_object_class_and_category_filter(
		f_object_category_filter,
		f_object_class_filter
	):
	return f"{f_object_category_filter()[:-1]}{f_object_class_filter()[2:]}"

@pytest.mark.parametrize(
	"value, expected",
	(
		(
			"a",
			"a",
		),
		(
			("a",),
			"a"
		),
		(
			("a", "b",),
			("a", "b",),
		),
		(
			["a",],
			"a"
		),
		(
			["a", "b",],
			["a", "b",],
		),
		(
			[],
			None
		),
		(
			{"a",},
			"a"
		),
		(
			{"a", "b",},
			{"a", "b",},
		),
		(
			{},
			None
		),
	),
	ids=[
		"Single value",
		"Tuple with single value",
		"Tuple",
		"List with single value",
		"List",
		"Empty List",
		"Set with single value",
		"Set",
		"Empty Set",
	]
)
def test_cleanup_attr_value(value, expected, f_ou_mixin: OrganizationalUnitMixin):
	assert f_ou_mixin.cleanup_attr_value(value=value) == expected

@pytest.mark.parametrize(
	"value, expected",
	(
		(
			"a",
			False,
		),
		(
			1,
			False,
		),
		(
			True,
			False,
		),
		(
			("a", "b"),
			True,
		),
		(
			["a", "b"],
			True,
		),
		(
			{"a", "b"},
			True,
		),
	),
	ids=[
		"Single str value",
		"Single int value",
		"Single bool value",
		"Tuple of str values",
		"List of str values",
		"Set of str values",
	]
)
def test_is_multi_value_attribute(value, expected, f_ou_mixin: OrganizationalUnitMixin):
	assert f_ou_mixin.is_multi_value_attribute(
		"mockAttribute",
		value
	) == expected

def test_is_multi_value_raises_validation_error(f_ou_mixin: OrganizationalUnitMixin):
	with pytest.raises(ValidationError):
		f_ou_mixin.is_multi_value_attribute("mockAttribute", b"some_bytes")

@pytest.mark.parametrize(
	"filter_type, filter_dict, expected",
	(
		# Simple cases
		(
			"include",
			{
				"objectClass":"user",
			},
			"(objectClass=user)"
		),
		(
			"exclude",
			{
				"objectClass":"user",
			},
			"(!(objectClass=user))"
		),
		(
			"iexact",
			{
				"objectClass":"user",
			},
			"(objectClass=user)"
		),
		(
			"contains",
			{
				"objectClass":"user",
			},
			"(objectClass=*user*)"
		),
		(
			"startswith",
			{
				"objectClass":"user",
			},
			"(objectClass=user*)"
		),
		(
			"endswith",
			{
				"objectClass":"user",
			},
			"(objectClass=*user)"
		),
		# Complex cases
		(
			"include",
			{
				"objectClass":"user",
				"distinguishedName":["testdn1", "testdn2"],
			},
			"(|(objectClass=user)(distinguishedName=testdn1)(distinguishedName=testdn2))"
		),
		(
			"exclude",
			{
				"objectClass":"user",
				"distinguishedName":"testdn"
			},
			"(&(!(objectClass=user))(!(distinguishedName=testdn)))"
		),
		(
			"exclude",
			{
				"objectClass":["user", "group"],
			},
			"(&(!(objectClass=user))(!(objectClass=group)))"
		),
		(
			"iexact",
			{
				"objectClass":["user", "group"],
				"distinguishedName":"testdn"
			},
			"(&(objectClass=user)(objectClass=group)(distinguishedName=testdn))"
		),
		(
			"contains",
			{
				"givenName":["john", "sam"],
				"sn":"johnson",
			},
			"(&(|(givenName=*john*)(givenName=*sam*))(sn=*johnson*))"
		),
		(
			"startswith",
			{
				"givenName":["john", "sam"],
				"sn":"johnson",
			},
			"(&(|(givenName=john*)(givenName=sam*))(sn=johnson*))"
		),
		(
			"endswith",
			{
				"givenName":["john", "sam"],
				"sn":"johnson",
			},
			"(&(|(givenName=*john)(givenName=*sam))(sn=*johnson))"
		),
		(
			"gte",
			{
				"mockAttribute1": 10
			},
			"(mockAttribute1>=10)",
		),
		(
			"gte",
			{
				"mockAttribute1": 5,
				"mockAttribute2": 1,
			},
			"(&(mockAttribute1>=5)(mockAttribute2>=1))",
		),
	),
)
def test_process_ldap_filter_type(
	filter_type: str,
	filter_dict: dict,
	expected: str,
	f_ou_mixin: OrganizationalUnitMixin
):
	assert f_ou_mixin.process_ldap_filter_type(
		filter_type, filter_dict).to_string() == expected

def test_process_ldap_filter_type_raises_on_iterable(f_ou_mixin: OrganizationalUnitMixin):
	with pytest.raises(ValidationError):
		f_ou_mixin.process_ldap_filter_type("gte", {
			"mockAttribute": [1]
		})

@pytest.mark.parametrize(
	"test_dict",
	(
		{
			"some_bad_key":{}
		},
		{
			"include":[]
		},
	),
	ids=[
		"Invalid filter dict key",
		"Invalid filter dict condition type"
	]
)
def test_validate_ldap_filter_dict_raises_validation_error(
		f_ou_mixin: OrganizationalUnitMixin,
		test_dict: dict,
	):
	with pytest.raises(ValidationError):
		f_ou_mixin.validate_filter_dict(filter_dict=test_dict)

def test_process_ldap_filter_no_defaults(f_ou_mixin: OrganizationalUnitMixin):
	expected = "(|(objectClass=person)(objectClass=user))"
	assert f_ou_mixin.process_ldap_filter(data_filter={
		"include":{
			"objectClass":[
				"person",
				"user",
			]
		}
	}, default_filter=False).to_string() == expected

def test_process_ldap_filter_with_defaults(
		f_ou_mixin: OrganizationalUnitMixin,
		f_object_class_and_category_filter,
	):
	result = f_ou_mixin.process_ldap_filter(
		data_filter={},
		default_filter=True
	).to_string()

	expected = f_object_class_and_category_filter
	assert result == expected

def test_process_ldap_filter_with_data_and_defaults(
	f_ou_mixin: OrganizationalUnitMixin,
	f_object_category_filter,
	f_object_class_filter,
	):
	result = f_ou_mixin.process_ldap_filter(
		data_filter={
			"exclude":{
				"objectClass":"user"
			}
		},
		default_filter=True
	).to_string()
	expected = f"{f_object_category_filter()[:-1]}{f_object_class_filter(user=None)[2:]}"
	expected = f"(&{expected}(!(objectClass=user)))"
	assert result == expected

