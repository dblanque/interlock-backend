########################### Standard Pytest Imports ############################
from pytest_mock import MockerFixture

################################################################################
from core.auth.ldap import LDAPBackend


def test_ldap_backend_call(mocker: MockerFixture):
	m_ldap_lib = mocker.patch("core.auth.ldap.ldap")
	LDAPBackend().authenticate()
	m_ldap_lib.authenticate.assert_called_once()
