import pytest
from unittest.mock import MagicMock, patch
from ldap3 import ServerPool, Connection
from ldap3.core.exceptions import LDAPException
import ssl
from core.exceptions import ldap as exc_ldap
from core.ldap.connector import (
	test_ldap_connection as func_test_ldap_connection,
)


@pytest.fixture
def f_base_params():
	return {
		"username": "testuser",
		"user_dn": "cn=testuser,dc=example,dc=com",
		"password": "user_password",
		"ldapAuthConnectionUser": "cn=admin,dc=example,dc=com",
		"ldapAuthConnectionPassword": "admin_password",
		"ldapAuthURL": ["ldap://localhost"],
		"ldapAuthConnectTimeout": 10,
		"ldapAuthReceiveTimeout": 10,
		"ldapAuthUseSSL": False,
		"ldapAuthUseTLS": False,
		"ldapAuthTLSVersion": "PROTOCOL_TLSv1_2",
	}


@pytest.fixture
def f_admin_params(f_base_params):
	params = f_base_params.copy()
	params.update(
		{
			"username": "admin",
			"password": "wrong_password",  # Should be overridden
		}
	)
	return params


@pytest.fixture
def f_invalid_timeout_params(f_base_params):
	params = f_base_params.copy()
	params.update(
		{"ldapAuthConnectTimeout": "invalid", "ldapAuthReceiveTimeout": None}
	)
	return params


@pytest.fixture
def f_tls_params(f_base_params):
	params = f_base_params.copy()
	params.update(
		{"ldapAuthUseTLS": True, "ldapAuthTLSVersion": "PROTOCOL_TLSv1_2"}
	)
	return params


def test_successful_connection(f_base_params, mocker):
	# Mock dependencies
	m_server_pool = mocker.MagicMock(spec=ServerPool)
	m_connection = mocker.MagicMock(spec=Connection)

	mocker.patch(
		"core.ldap.connector.ldap3.ServerPool", return_value=m_server_pool
	)
	mocker.patch(
		"core.ldap.connector.ldap3.Connection", return_value=m_connection
	)
	mocker.patch("core.ldap.connector.ldap3.Server")
	m_format = mocker.patch(
		"core.ldap.connector.import_func", return_value=lambda x: x
	)

	# Execute
	result = func_test_ldap_connection(**f_base_params)

	# Assertions
	assert result == m_connection
	m_connection.bind.assert_called_once()
	m_format.assert_called_once()


def test_admin_connection_credentials(f_admin_params, mocker):
	# Mock dependencies
	m_connection = mocker.patch(
		"core.ldap.connector.ldap3.Connection",
		return_value=mocker.MagicMock(spec=Connection),
	)
	mocker.patch("core.ldap.connector.ldap3.ServerPool")
	mocker.patch("core.ldap.connector.ldap3.Server")

	# Execute
	func_test_ldap_connection(**f_admin_params)

	# Verify admin credentials were used
	args, kwargs = m_connection.call_args
	assert kwargs["user"] == f_admin_params["ldapAuthConnectionUser"]
	assert kwargs["password"] == f_admin_params["ldapAuthConnectionPassword"]


def test_invalid_timeout_fallbacks(f_invalid_timeout_params, mocker):
	# Mock logger
	m_logger = mocker.patch("core.ldap.connector.logger")
	mocker.patch("core.ldap.connector.ldap3.Connection")
	mocker.patch("core.ldap.connector.ldap3.ServerPool")
	mocker.patch("core.ldap.connector.ldap3.Server")

	# Execute
	func_test_ldap_connection(**f_invalid_timeout_params)

	# Verify fallback to default timeouts
	m_logger.info.assert_any_call(
		"ldapAuthConnectTimeout is not an int, using default"
	)
	m_logger.info.assert_any_call(
		"ldapAuthReceiveTimeout is not an int, using default"
	)


def test_tls_connection(f_tls_params, mocker):
	# Mock dependencies
	m_connection = mocker.MagicMock(spec=Connection)
	mocker.patch(
		"core.ldap.connector.ldap3.Connection", return_value=m_connection
	)
	mocker.patch("core.ldap.connector.ldap3.ServerPool")
	mocker.patch("core.ldap.connector.ldap3.Server")
	mocker.patch("core.ldap.connector.ldap3.Tls")
	mocker.patch(
		"core.ldap.connector.getattr", return_value=ssl.PROTOCOL_TLSv1_2
	)

	# Execute
	func_test_ldap_connection(**f_tls_params)

	# Verify TLS was used
	m_connection.start_tls.assert_called_once()


def test_connection_failure(f_base_params, mocker):
	# Mock failure
	mocker.patch(
		"core.ldap.connector.ldap3.Connection", side_effect=LDAPException
	)
	mocker.patch("core.ldap.connector.logger")

	# Execute and verify exception
	with pytest.raises(exc_ldap.CouldNotOpenConnection):
		func_test_ldap_connection(**f_base_params)


def test_bind_failure(f_base_params, mocker):
	# Mock connection succeeds but bind fails
	m_connection = mocker.MagicMock(spec=Connection)
	m_connection.bind.side_effect = LDAPException("Bind failed")
	mocker.patch(
		"core.ldap.connector.ldap3.Connection", return_value=m_connection
	)
	mocker.patch("core.ldap.connector.logger")

	# Execute and verify exception
	with pytest.raises(exc_ldap.CouldNotOpenConnection):
		func_test_ldap_connection(**f_base_params)


@pytest.mark.parametrize(
	"url_input,expected",
	[
		("ldap://server", ["ldap://server"]),
		(["ldap://s1", "ldap://s2"], ["ldap://s1", "ldap://s2"]),
	],
)
def test_url_handling(url_input, expected, f_base_params, mocker):
	# Mock dependencies
	mocker.patch(
		"core.ldap.connector.ldap3.Connection",
		return_value=mocker.MagicMock(spec=Connection),
	)
	m_server_pool = mocker.MagicMock(spec=ServerPool)
	mocker.patch(
		"core.ldap.connector.ldap3.ServerPool", return_value=m_server_pool
	)

	# Modify URL parameter
	params = f_base_params.copy()
	params["ldapAuthURL"] = url_input

	# Execute
	func_test_ldap_connection(**params)

	# Verify URL handling
	assert m_server_pool.add.call_count == len(expected)
	for call in m_server_pool.add.call_args_list:
		assert call[0][0].host in [
			u.split("//")[1] if u else None for u in expected
		]


def test_url_handling_exception(f_base_params, mocker):
	# Mock dependencies
	mocker.patch(
		"core.ldap.connector.ldap3.Connection",
		return_value=mocker.MagicMock(spec=Connection),
	)
	m_server_pool = mocker.MagicMock(spec=ServerPool)
	mocker.patch(
		"core.ldap.connector.ldap3.ServerPool", return_value=m_server_pool
	)

	# Modify URL parameter
	params = f_base_params.copy()
	params["ldapAuthURL"] = None

	# Execute
	with pytest.raises(TypeError, match="auth_url must be str or Iterable."):
		func_test_ldap_connection(**params)
