########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType
################################################################################
from core.views.mixins.ldap.organizational_unit import (
	OrganizationalUnitMixin,
	LDAP_DEFAULT_DIRTREE_FILTER
)

@pytest.fixture
def f_ou_mixin(mocker: MockerFixture):
	m_mixin = OrganizationalUnitMixin()
	m_mixin.ldap_connection = mocker.MagicMock()
	return m_mixin

def test_process_ldap_filter_no_defaults(f_ou_mixin: OrganizationalUnitMixin):
	expected = "(|(objectClass=person)(objectClass=user))"
	assert f_ou_mixin.process_ldap_filter(data_filter={
		"include":{
			"objectClass":[
				"person",
				"user",
			]
		}
	}, local_filter=False).to_string() == expected

# def test_process_ldap_filter_with_defaults(f_ou_mixin: OrganizationalUnitMixin):
# 	defaults_filter = None
# 	for k in LDAP_DEFAULT_DIRTREE_FILTER["include"]["objectCategory"]:
# 		defaults_filter
# 	expected = "(|(objectClass=person)(objectClass=user))"
# 	assert f_ou_mixin.process_ldap_filter(data_filter={
# 		"include":{
# 			"objectClass":[
# 				"person",
# 				"user",
# 			]
# 		}
# 	}).to_string() == expected
