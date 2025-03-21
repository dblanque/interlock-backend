import pytest
from pytest_mock import MockType
from core.ldap.connector import LDAPConnector
from core.models.choices.log import (
	LOG_ACTION_OPEN,
	LOG_ACTION_CLOSE,
	LOG_CLASS_CONN
)


def test_enter_context_manager(mocker, f_user, f_runtime_settings):
	# Mock RuntimeSettings
	f_runtime_settings.LDAP_LOG_OPEN_CONNECTION = True
	mocker.patch("core.ldap.connector.RuntimeSettings", f_runtime_settings)

	# Mock DBLogMixin.log
	m_log: MockType = mocker.patch("core.ldap.connector.DBLogMixin.log")

	# Create LDAPConnector instance
	connector = LDAPConnector(user=f_user)
	
	# Mock bind method
	mocker.patch.object(connector, "bind")
	
	# Enter context manager
	with connector as c:
		assert c == connector  # Ensure the context manager returns self
		m_log.assert_called_once_with(
			user_id=f_user.id,
			actionType=LOG_ACTION_OPEN,
			objectClass=LOG_CLASS_CONN,
			affectedObject=f"{connector.uuid}",
		)

@pytest.mark.parametrize(
	"logging, authenticating, expects_logging",
	(
		(True, False, True), # LOG, NOT AUTHENTICATING
		(True, True, False), # LOG, AUTHENTICATING
		(False, True, False), # NO LOG, AUTHENTICATING
		(False, False, False), # NO LOG, NOT AUTHENTICATING
	)
)
def test_exit_context_manager(logging, authenticating, expects_logging, mocker, f_user, f_runtime_settings, f_connection):
	# Mock RuntimeSettings
	f_runtime_settings.LDAP_LOG_CLOSE_CONNECTION = logging
	mocker.patch("core.ldap.connector.RuntimeSettings", f_runtime_settings)

	# Mock DBLogMixin.log
	m_log: MockType = mocker.patch("core.ldap.connector.DBLogMixin.log")

	# Create LDAPConnector instance
	connector = LDAPConnector(user=f_user, is_authenticating=authenticating)
	connector.connection = f_connection

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


def test_validate_entered():
	pass