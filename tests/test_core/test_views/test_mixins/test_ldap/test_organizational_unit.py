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
	flt = None
	for value in LDAP_DEFAULT_DIRTREE_FILTER["include"]["objectCategory"]:
		flt = join_ldap_filter(
			filter_string=flt,
			filter_to_add=f"objectCategory={value}",
			expression="|"
		)
	return flt

@pytest.fixture
def f_object_class_filter():
	flt = None
	for value in LDAP_DEFAULT_DIRTREE_FILTER["include"]["objectClass"]:
		flt = join_ldap_filter(
			filter_string=flt,
			filter_to_add=f"objectClass={value}",
			expression="|"
		)
	return flt

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
