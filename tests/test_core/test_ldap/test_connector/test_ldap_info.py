import pytest
from ldap3 import ALL
from core.ldap.connector import LDAPInfo


@pytest.fixture
def f_ldap_info(mocker, f_user, f_server_pool, f_server, f_ldap_connection):
	mocker.patch("core.ldap.connector.LDAPInfo.__init__", return_value=None)
	mocker.patch("core.ldap.connector.ldap3.ServerPool", return_value=f_server_pool)
	mocker.patch("core.ldap.connector.ldap3.Server", return_value=f_server)
	mocker.patch("core.ldap.connector.ldap3.Connection", return_value=f_ldap_connection)
	mocker.patch("core.ldap.connector.aes_decrypt", return_value="somepassword")
	m_ldap_info = LDAPInfo(user=f_user)
	m_ldap_info.connection = f_ldap_connection
	m_ldap_info._entered = True
	return m_ldap_info


def test_init_sets_get_ldap_info(mocker, f_user):
	m_super_init = mocker.patch("core.ldap.connector.LDAPConnector.__init__")
	m_refresh = mocker.patch("core.ldap.connector.LDAPInfo.refresh_server_info")

	ldap_info = LDAPInfo(user=f_user)

	m_super_init.assert_called_once_with(
		user=f_user,
		force_admin=False,
		get_ldap_info=ALL,  # Make sure this matches your import
	)
	m_refresh.assert_called_once()


def test_refresh_server_info(mocker, f_ldap_info, f_server, f_server_pool):
	# Setup mocks
	f_server_pool.get_current_server.return_value = f_server
	f_ldap_info.connection.server_pool = f_server_pool

	# Execute
	f_ldap_info.refresh_server_info()

	# Verify
	f_server_pool.get_current_server.assert_called_once_with(f_ldap_info.connection)
	f_server.get_info_from_server.assert_called_once_with(f_ldap_info.connection)
	assert f_ldap_info.schema == f_server.schema
	assert f_ldap_info.info == f_server.info


def test_get_domain_root_success(mocker, f_ldap_info):
	# Setup mock info
	expected_domain = "dc=example,dc=com"
	f_ldap_info.info = mocker.MagicMock()
	f_ldap_info.info.other = {"defaultNamingContext": [expected_domain]}

	# Execute and verify
	assert f_ldap_info.get_domain_root() == expected_domain


def test_get_domain_root_failure(mocker, f_ldap_info):
	# Setup mock info with missing key
	f_ldap_info.info = mocker.MagicMock()
	f_ldap_info.info.other = {}
	m_logger = mocker.patch("core.ldap.connector.logger")

	# Execute and verify
	assert f_ldap_info.get_domain_root() is None
	m_logger.exception.assert_called_once()


def test_get_schema_naming_context_success(mocker, f_ldap_info):
	# Setup mock info
	expected_schema = "cn=schema,cn=config"
	f_ldap_info.info = mocker.MagicMock()
	f_ldap_info.info.other = {"schemaNamingContext": [expected_schema]}

	# Execute and verify
	assert f_ldap_info.get_schema_naming_context() == expected_schema


def test_get_schema_naming_context_failure(mocker, f_ldap_info):
	# Setup mock info with missing key
	f_ldap_info.info = mocker.MagicMock()
	f_ldap_info.info.other = {}
	m_logger = mocker.patch("core.ldap.connector.logger")

	# Execute and verify
	assert f_ldap_info.get_schema_naming_context() is None
	m_logger.exception.assert_called_once()


def test_get_forest_root_success(mocker, f_ldap_info):
	# Setup mock info
	expected_forest = "dc=forest,dc=example,dc=com"
	f_ldap_info.info = mocker.MagicMock()
	f_ldap_info.info.other = {"rootDomainNamingContext": [expected_forest]}

	# Execute and verify
	assert f_ldap_info.get_forest_root() == expected_forest


def test_get_forest_root_failure(mocker, f_ldap_info):
	# Setup mock info with missing key
	f_ldap_info.info = mocker.MagicMock()
	f_ldap_info.info.other = {}
	m_logger = mocker.patch("core.ldap.connector.logger")

	# Execute and verify
	assert f_ldap_info.get_forest_root() is None
	m_logger.exception.assert_called_once()


def test_info_methods_with_no_info(mocker, f_ldap_info):
	# Test all getter methods when info is None
	f_ldap_info.info = None
	m_logger = mocker.patch("core.ldap.connector.logger")

	assert f_ldap_info.get_domain_root() is None
	assert f_ldap_info.get_schema_naming_context() is None
	assert f_ldap_info.get_forest_root() is None
	assert m_logger.exception.call_count == 3
