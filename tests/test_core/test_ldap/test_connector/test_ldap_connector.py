import pytest
from pytest_mock import MockType
from core.ldap.connector import LDAPConnector, sync_user_relations
from ldap3.core.exceptions import LDAPException
from core.ldap.adsi import search_filter_add, LDAP_FILTER_OR
from ldap3 import SUBTREE as ldap3_SUBTREE, ALL_ATTRIBUTES as ldap3_ALL_ATTRIBUTES
from core.exceptions.ldap import CouldNotOpenConnection
from core.models.choices.log import LOG_ACTION_OPEN, LOG_ACTION_CLOSE, LOG_CLASS_CONN
from core.models.user import USER_TYPE_LDAP
from inspect import getfullargspec
from copy import deepcopy
import ssl


@pytest.fixture
def f_ldap_connector(
	mocker,
	f_runtime_settings,
	f_user,
	f_ldap_connection,
	f_tls,
	f_server,
	f_server_pool,
):
	mocker.patch("core.ldap.connector.RuntimeSettings", f_runtime_settings)
	mocker.patch("core.ldap.connector.ldap3.Server", return_value=f_server)
	mocker.patch("core.ldap.connector.ldap3.ServerPool", return_value=f_server_pool)
	mocker.patch("core.ldap.connector.ldap3.Tls", return_value=f_tls)
	mocker.patch("core.ldap.connector.aes_decrypt", return_value="somepassword")
	connector = LDAPConnector(user=f_user)
	connector.connection = f_ldap_connection
	# Bypass context manager validation to avoid bind/unbind patch
	connector._entered = True
	return connector

@pytest.mark.parametrize(
	"authenticating",
	(
		True,
		False,
	),
	ids=lambda x: "Is authenticating" if x else "Is not authenticating",
)
def test_enter_context_manager(authenticating, mocker, f_user, f_runtime_settings):
	# Mock RuntimeSettings
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
		if not authenticating:
			m_log.assert_called_once_with(
				user=f_user.id,
				operation_type=LOG_ACTION_OPEN,
				log_target_class=LOG_CLASS_CONN,
				log_target=f"{connector.uuid}",
			)
		else:
			m_log.assert_not_called()

@pytest.mark.parametrize(
	"authenticating",
	(
		True,
		False,
	),
	ids=lambda x: "Is authenticating" if x else "Is not authenticating",
)
def test_exit_context_manager(
	authenticating, mocker, f_user, f_runtime_settings, f_ldap_connection
):
	# Mock RuntimeSettings
	mocker.patch("core.ldap.connector.RuntimeSettings", f_runtime_settings)
	mocker.patch("core.ldap.connector.aes_decrypt", return_value="somepassword")

	# Mock DBLogMixin.log
	m_log: MockType = mocker.patch("core.ldap.connector.DBLogMixin.log")

	# Create LDAPConnector instance
	connector = LDAPConnector(user=f_user, is_authenticating=authenticating)
	connector.connection = f_ldap_connection

	# Mock context entered
	connector._entered = True

	# Exit context manager
	connector.__exit__(None, None, None)

	# Verify unbind and logging
	f_ldap_connection.unbind.assert_called_once()
	if not authenticating:
		m_log.assert_called_once_with(
			user=f_user.id,
			operation_type=LOG_ACTION_CLOSE,
			log_target_class=LOG_CLASS_CONN,
			log_target=f"{connector.uuid}",
		)
	else:
		m_log.assert_not_called()


def test_validate_entered_exception(mocker, f_user):
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
	ids=lambda x: "Admin Forced Bind" if x else "User Bind",
)
def test_init_with_valid_user(
	force_admin,
	mocker,
	f_admin_dn,
	f_user,
	f_ldap_connection,
	f_server_pool,
	f_runtime_settings,
	f_tls,
):
	connector_kwargs = {"force_admin": force_admin}
	if "force_admin" in connector_kwargs:
		if connector_kwargs["force_admin"]:
			expected_dn = f_admin_dn
		else:
			connector_kwargs["user"] = f_user
			expected_dn = f_user.dn

	# Mock RuntimeSettings
	mocker.patch("core.ldap.connector.RuntimeSettings", f_runtime_settings)

	# Mock ldap3.Connection
	mocker.patch("core.ldap.connector.ldap3.Connection", return_value=f_ldap_connection)
	mocker.patch("core.ldap.connector.ldap3.ServerPool", return_value=f_server_pool)
	mocker.patch("core.ldap.connector.ldap3.Tls", return_value=f_tls)
	mocker.patch("core.ldap.connector.aes_decrypt", return_value="somepassword")

	# Create LDAPConnector instance
	with LDAPConnector(**connector_kwargs) as connector:
		# Verify connection is established
		assert connector.connection == f_ldap_connection
		assert connector.server_pool == f_server_pool
		assert connector.user_dn.lower() == expected_dn


def test_init_with_invalid_user(mocker, f_runtime_settings):
	# Mock RuntimeSettings
	mocker.patch("core.ldap.connector.RuntimeSettings", f_runtime_settings)

	# Test with no user
	with pytest.raises(Exception, match="No valid user in LDAP Connector."):
		LDAPConnector(user=None)


def test_init_with_invalid_user_dn(mocker, f_runtime_settings):
	# Mock RuntimeSettings
	mocker.patch("core.ldap.connector.RuntimeSettings", f_runtime_settings)
	mocker.patch("core.ldap.connector.aes_decrypt", return_value="somepassword")
	f_runtime_settings.LDAP_AUTH_CONNECTION_USER_DN = None
	m_user = mocker.MagicMock()
	m_user.dn = None
	m_user.user_type = USER_TYPE_LDAP

	# Test with no user
	with pytest.raises(ValueError, match="No user_dn was provided for LDAP Connector."):
		LDAPConnector(user=m_user)

@pytest.fixture
def tls_version_enum(f_runtime_settings):
	return f_runtime_settings.LDAP_AUTH_TLS_VERSION

@pytest.fixture
def tls_version_str(f_runtime_settings):
	return getattr(ssl, f_runtime_settings.LDAP_AUTH_TLS_VERSION.name)

@pytest.mark.parametrize(
	"tls_version",
	(
		"tls_version_enum",
		"tls_version_str",
	)
)
def test_log_init(tls_version, mocker, f_ldap_connector, f_runtime_settings, request):
	_tls_version = request.getfixturevalue(tls_version)
	m_logger: MockType = mocker.patch("core.ldap.connector.logger")
	m_logger_debug: MockType = m_logger.debug
	f_ldap_connector.__log_init__(user="testuser", tls_version=_tls_version)
	m_logger_debug.call_count == 8

@pytest.mark.parametrize(
	"use_tls",
	(
		True,
		False,
	),
	ids=lambda x: "TLS Enabled" if x else "Plain Connection",
)
def test_bind_success(
	use_tls, mocker, f_user, f_runtime_settings, f_ldap_connection, f_server_pool, f_tls
):
	# Mock RuntimeSettings
	mocker.patch("core.ldap.connector.RuntimeSettings", f_runtime_settings)
	f_runtime_settings.LDAP_AUTH_USE_TLS = use_tls

	# Mock ldap3.Connection
	mocker.patch("core.ldap.connector.ldap3.Connection", return_value=f_ldap_connection)
	mocker.patch("core.ldap.connector.ldap3.ServerPool", return_value=f_server_pool)
	mocker.patch("core.ldap.connector.ldap3.Tls", return_value=f_tls)
	mocker.patch("core.ldap.connector.aes_decrypt", return_value="somepassword")

	# Create LDAPConnector instance
	connector = LDAPConnector(user=f_user)

	# Emulate context entered
	connector._entered = True
	connector._temp_password = "password"

	# Call bind
	connector.bind()

	# Verify connection is established
	assert connector.connection == f_ldap_connection
	if use_tls:
		f_ldap_connection.start_tls.assert_called_once()
	f_ldap_connection.bind.assert_called_once()


def test_bind_connection_raises_ldap_exception(
	mocker, f_user, f_runtime_settings, f_server_pool, f_tls
):
	# Mock RuntimeSettings
	mocker.patch("core.ldap.connector.RuntimeSettings", f_runtime_settings)

	# Patch connector classes
	mocker.patch("core.ldap.connector.ldap3.Connection", side_effect=LDAPException)
	mocker.patch("core.ldap.connector.ldap3.ServerPool", return_value=f_server_pool)
	mocker.patch("core.ldap.connector.ldap3.Tls", return_value=f_tls)
	mocker.patch("core.ldap.connector.aes_decrypt", return_value="somepassword")

	# Create LDAPConnector instance
	connector = LDAPConnector(user=f_user)

	# Emulate context entered
	connector._entered = True
	connector._temp_password = "password"

	# Call bind
	with pytest.raises(CouldNotOpenConnection):
		connector.bind()


def test_bind_raises_ldap_exception(
	mocker, f_user, f_runtime_settings, f_ldap_connection, f_server_pool, f_tls
):
	# Mock RuntimeSettings
	mocker.patch("core.ldap.connector.RuntimeSettings", f_runtime_settings)

	# Patch connector classes
	f_ldap_connection.bind.side_effect = LDAPException
	mocker.patch("core.ldap.connector.ldap3.Connection", return_value=f_ldap_connection)
	mocker.patch("core.ldap.connector.ldap3.ServerPool", return_value=f_server_pool)
	mocker.patch("core.ldap.connector.ldap3.Tls", return_value=f_tls)
	mocker.patch("core.ldap.connector.aes_decrypt", return_value="somepassword")

	# Create LDAPConnector instance
	connector = LDAPConnector(user=f_user)

	# Emulate context entered
	connector._entered = True
	connector._temp_password = "password"

	# Call bind
	with pytest.raises(CouldNotOpenConnection):
		connector.bind()


def test_rebind_success(
	mocker,
	f_user,
	f_ldap_connector,
	f_ldap_connection,
):
	# Patch connector classes
	mocker.patch("core.ldap.connector.ldap3.Connection.rebind", return_value="result")
	f_ldap_connection.result = "result"

	result = f_ldap_connector.rebind(f_user.dn, "somepassword")
	assert result == f_ldap_connection.result
	f_ldap_connection.rebind.assert_called_once_with(
		user=f_user.dn, password="somepassword", read_server_info=True
	)


def test_rebind_password_exception(
	mocker,
	f_user,
	f_ldap_connection,
	f_ldap_connector,
):
	# Patch connector classes
	mocker.patch("core.ldap.connector.ldap3.Connection.rebind", return_value="result")
	f_ldap_connection.result = "result"

	f_ldap_connector.connection = f_ldap_connection
	with pytest.raises(ValueError, match="Password length smaller than one, unbinding connection."):
		f_ldap_connector.rebind(f_user.dn, None)


def test_rebind_ldap_exception(
	f_user,
	f_ldap_connection,
	f_ldap_connector,
):
	# Patch connector classes
	f_ldap_connection.rebind.side_effect = LDAPException

	f_ldap_connector.connection = f_ldap_connection
	assert f_ldap_connector.rebind(f_user.dn, "somepassword") is None


def test_get_user_success(
	mocker,
	f_user,
	f_runtime_settings,
	f_ldap_connection,
	f_ldap_connector,
):
	# Patch connector classes
	mocker.patch("core.ldap.connector.ldap3.Connection", return_value=f_ldap_connection)
	mocker.patch("core.ldap.connector.aes_decrypt", return_value="somepassword")

	m_get_or_create_user: MockType = mocker.patch.object(
		LDAPConnector, "_get_or_create_user", return_value=f_user
	)
	expected_filter = search_filter_add(
		f"sAMAccountName={f_user.username}",
		f"mail={f_user.username}",
		LDAP_FILTER_OR,
	)

	f_ldap_connector.connection = f_ldap_connection
	f_ldap_connector.connection.response = [f_user]
	result = f_ldap_connector.get_user(username=f_user.username)
	assert result == f_user
	f_ldap_connection.search.assert_called_once_with(
		search_base=f_runtime_settings.LDAP_AUTH_SEARCH_BASE,
		search_filter=expected_filter,
		search_scope=ldap3_SUBTREE,
		attributes=ldap3_ALL_ATTRIBUTES,
		get_operational_attributes=True,
		size_limit=1,
	)
	m_get_or_create_user.assert_called_once_with(f_ldap_connection.response[0])


def test_get_user_failure(mocker, f_ldap_connector, f_runtime_settings, f_ldap_connection):
	# Mock RuntimeSettings
	mocker.patch("core.ldap.connector.RuntimeSettings", f_runtime_settings)

	# Patch connector classes
	mocker.patch("core.ldap.connector.ldap3.Connection", return_value=f_ldap_connection)
	mocker.patch("core.ldap.connector.aes_decrypt", return_value="somepassword")

	# Mock connection.search
	f_ldap_connection.search.return_value = None

	f_ldap_connector.connection = f_ldap_connection

	# Test get_user
	result = f_ldap_connector.get_user(username="invalid_user")
	assert result is None


@pytest.fixture
def f_user_data(mocker, f_user):
	m_user_data = mocker.MagicMock()
	m_user_data.attributes = {
		"sAMAccountName": f_user.username,
		"mail": [f_user.email],
		"cn": ["Test User"],
	}
	m_user_data.fields = {
		"username": f_user.username,
		"email": f_user.email,
	}
	m_user_data.get.return_value = m_user_data.attributes
	return m_user_data


@pytest.fixture
def f_empty_user_data(mocker):
	m_user_data = mocker.MagicMock()
	m_user_data.attributes = None
	m_user_data.get.return_value = m_user_data.attributes
	return m_user_data


@pytest.mark.parametrize(
	"created",
	(
		False,
		True,
	),
	ids=lambda x: "User Created" if x else "User Updated",
)
def test_get_or_create_user(created, f_ldap_connector, f_user_data, f_user, mocker):
	# Mock dependencies
	m_user_model = mocker.MagicMock()
	m_user_model.objects.update_or_create.return_value = (f_user, created)

	m_clean_func = mocker.MagicMock(return_value=f_user_data.fields)
	m_user_fields = deepcopy(f_user_data.fields)
	m_sync_func = mocker.MagicMock()

	# Patch dependencies
	mocker.patch("core.ldap.connector.get_user_model", return_value=m_user_model)
	mocker.patch("core.ldap.connector.import_func", return_value=m_clean_func)
	mocker.patch("core.ldap.connector.sync_user_relations", m_sync_func)
	mocker.patch(
		"core.ldap.connector.getfullargspec", return_value=getfullargspec(sync_user_relations)
	)

	# Execute
	result = f_ldap_connector._get_or_create_user(f_user_data)

	# Assertions
	assert result == f_user
	m_user_model.objects.update_or_create.assert_called_once()
	m_clean_func.assert_called_once_with(m_user_fields)
	m_sync_func.assert_called_once_with(
		f_user, f_user_data.attributes, connection=f_ldap_connector.connection
	)
	if created:
		f_user.set_unusable_password.assert_called_once()
		f_user.save.assert_called_once()


def test_get_or_create_user_empty_attributes(f_ldap_connector, f_empty_user_data, mocker):
	# Mock logger
	m_logger = mocker.patch("core.ldap.connector.logger")

	# Execute
	result = f_ldap_connector._get_or_create_user(f_empty_user_data)

	# Assertions
	assert result is None
	m_logger.warning.assert_called_once_with("LDAP user attributes empty")


def test_get_or_create_user_invalid_sync_args(f_ldap_connector, f_user, f_user_data, mocker):
	m_user_model = mocker.MagicMock()
	m_user_model.objects.update_or_create.return_value = (f_user, True)
	mocker.patch("core.ldap.connector.get_user_model", return_value=m_user_model)

	# Setup mock sync function with unexpected argument
	m_sync_func = mocker.MagicMock()
	m_sync_func.__name__ = "sync_user_relations"
	mocker.patch("core.ldap.connector.sync_user_relations", m_sync_func)
	mocker.patch(
		"core.ldap.connector.getfullargspec",
		return_value=mocker.MagicMock(kwonlyargs=["invalid_arg"]),
	)

	# Execute and verify exception
	with pytest.raises(
		TypeError,
		match="Unknown kw argument invalid_arg in signature for LDAP_AUTH_SYNC_USER_RELATIONS",
	):
		f_ldap_connector._get_or_create_user(f_user_data)
