import pytest
from pytest_mock import MockType
from core.ldap.connector import LDAPConnector
from ldap3 import Tls as ldap3_Tls
from core.models.choices.log import (
	LOG_ACTION_OPEN,
	LOG_ACTION_CLOSE,
	LOG_CLASS_CONN
)

def f_enter_exit_logging_cases():
	return (
		(True, False, True), # LOG, NOT AUTHENTICATING
		(True, True, False), # LOG, AUTHENTICATING
		(False, True, False), # NO LOG, AUTHENTICATING
		(False, False, False), # NO LOG, NOT AUTHENTICATING
	)


@pytest.mark.parametrize(
	"logging, authenticating, expects_logging",
	f_enter_exit_logging_cases()
)
def test_enter_context_manager(logging, authenticating, expects_logging, mocker, f_user, f_runtime_settings):
	# Mock RuntimeSettings
	f_runtime_settings.LDAP_LOG_OPEN_CONNECTION = logging
	mocker.patch("core.ldap.connector.RuntimeSettings", f_runtime_settings)
	mocker.patch("core.ldap.connector.aes_decrypt", return_value="somepassword")

	# Mock DBLogMixin.log
	m_log: MockType = mocker.patch("core.ldap.connector.DBLogMixin.log")

	# Create LDAPConnector instance
	connector = LDAPConnector(user=f_user, is_authenticating=authenticating)
	
	# Mock bind method
	mocker.patch.object(connector, "bind")
	
	# Enter context manager
	with connector as c:
		assert c == connector  # Ensure the context manager returns self
		if expects_logging:
			m_log.assert_called_once_with(
				user_id=f_user.id,
				actionType=LOG_ACTION_OPEN,
				objectClass=LOG_CLASS_CONN,
				affectedObject=f"{connector.uuid}",
			)
		else:
			m_log.assert_not_called()

@pytest.mark.parametrize(
	"logging, authenticating, expects_logging",
	f_enter_exit_logging_cases()
)
def test_exit_context_manager(logging, authenticating, expects_logging, mocker, f_user, f_runtime_settings, f_connection):
	# Mock RuntimeSettings
	f_runtime_settings.LDAP_LOG_CLOSE_CONNECTION = logging
	mocker.patch("core.ldap.connector.RuntimeSettings", f_runtime_settings)
	mocker.patch("core.ldap.connector.aes_decrypt", return_value="somepassword")

	# Mock DBLogMixin.log
	m_log: MockType = mocker.patch("core.ldap.connector.DBLogMixin.log")

	# Create LDAPConnector instance
	connector = LDAPConnector(user=f_user, is_authenticating=authenticating)
	connector.connection = f_connection
	connector._entered = True

	# Exit context manager
	connector.__exit__(None, None, None)

	# Verify unbind and logging
	f_connection.unbind.assert_called_once()
	if expects_logging:
		m_log.assert_called_once_with(
			user_id=f_user.id,
			actionType=LOG_ACTION_CLOSE,
			objectClass=LOG_CLASS_CONN,
			affectedObject=f"{connector.uuid}",
		)
	else:
		m_log.assert_not_called()


def test_validate_entered_exception(mocker, f_user, f_connection):
	mocker.patch("core.ldap.connector.aes_decrypt", return_value="somepassword")
	connector = LDAPConnector(user=f_user)
	with pytest.raises(Exception):
		connector.__validate_entered__()

@pytest.mark.parametrize(
	"force_admin",
	(
		True,
		False,
	),
)
def test_init_with_valid_user(force_admin, mocker, f_admin_dn, f_user, f_connection, f_server_pool, f_runtime_settings):
	connector_kwargs = {
		"force_admin": force_admin
	}
	if "force_admin" in connector_kwargs:
		if connector_kwargs["force_admin"]:
			expected_dn = f_admin_dn
		else:
			connector_kwargs["user"] = f_user
			expected_dn = f_user.dn

	# Mock RuntimeSettings
	mocker.patch("core.ldap.connector.RuntimeSettings", f_runtime_settings)

	# Mock ldap3.Connection
	mocker.patch("core.ldap.connector.ldap3.Connection", return_value=f_connection)
	mocker.patch("core.ldap.connector.ldap3.ServerPool", return_value=f_server_pool)
	mocker.patch("core.ldap.connector.ldap3.Tls", return_value=mocker.Mock(spec=ldap3_Tls))
	mocker.patch("core.ldap.connector.aes_decrypt", return_value="somepassword")

	# Create LDAPConnector instance
	with LDAPConnector(**connector_kwargs) as connector:
		# Verify connection is established
		assert connector.connection == f_connection
		assert connector.server_pool == f_server_pool
		assert connector.user_dn.lower() == expected_dn

def test_init_with_invalid_user(mocker, f_runtime_settings):
	# Mock RuntimeSettings
	mocker.patch("core.ldap.connector.RuntimeSettings", return_value=f_runtime_settings)

	# Test with no user
	with pytest.raises(Exception, match="No valid user in LDAP Connector."):
		LDAPConnector(user=None)