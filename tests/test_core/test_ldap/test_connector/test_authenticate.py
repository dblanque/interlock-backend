import pytest
from pytest_mock import MockType
from interlock_backend.test_settings import DEFAULT_SUPERUSER_USERNAME
from core.models.user import USER_TYPE_LDAP, USER_PASSWORD_FIELDS
from core.ldap.connector import authenticate


@pytest.fixture
def m_request_data():
	return {"username": "testuser", "password": "somepassword"}


@pytest.fixture
def m_encrypted_password():
	return ("encrypted_aes_key", "ciphertext", "nonce", "tag")


@pytest.fixture
def m_ldap_connector(mocker) -> MockType:
	"""Fixture to mock LDAPConnector and its context manager."""
	m_connector = mocker.patch("core.ldap.connector.LDAPConnector", return_value=mocker.MagicMock())
	return m_connector


@pytest.fixture
def m_ldc(mocker, m_connection) -> MockType:
	"""Fixture to mock the LDAPConnector context manager (ldc)."""
	m_ldc = mocker.Mock()
	m_ldc.connection = m_connection
	return m_ldc


@pytest.fixture
def m_connection(mocker) -> MockType:
	"""Fixture to mock the LDAP connection."""
	m_connection = mocker.Mock(name="m_connection")
	m_connection.unbind = mocker.Mock(name="m_connection_unbind")
	m_connection.rebind = mocker.Mock(name="m_connection_rebind")
	return m_connection


@pytest.fixture
def m_user(mocker, m_user_dn) -> MockType:
	"""Fixture to mock the User object."""
	m_user = mocker.Mock(name="m_user")
	m_user.dn = m_user_dn
	m_user.save = mocker.Mock(name="m_user_save")
	return m_user


def test_authenticate_connection_is_none(
	mocker, m_runtime_settings, m_request_data, m_ldap_connector
):
	"""Test that authenticate returns None when the LDAP connection is None."""
	mocker.patch("core.config.runtime.RuntimeSettings", return_value=m_runtime_settings)
	m_ldap_connector.return_value.__enter__.return_value.connection = None

	assert authenticate(**m_request_data) is None


def test_authenticate_get_user_is_none(
	mocker, m_runtime_settings, m_request_data, m_ldap_connector, m_ldc
):
	"""Test that authenticate returns None when get_user returns None."""
	mocker.patch("core.config.runtime.RuntimeSettings", return_value=m_runtime_settings)
	m_ldc.get_user.return_value = None
	m_ldap_connector.return_value.__enter__.return_value = m_ldc

	result = authenticate(**m_request_data)

	m_ldc.get_user.assert_called_once()
	m_ldc.connection.unbind.assert_called_once()
	assert result is None


@pytest.mark.parametrize("expected_rebind_return", [False, None])
def test_authenticate_rebind_is_not_truthy(
	expected_rebind_return,
	mocker,
	m_runtime_settings,
	m_request_data,
	m_ldap_connector,
	m_ldc,
	m_user,
):
	"""Test that authenticate returns None when rebind returns a non-truthy value."""
	mocker.patch("core.config.runtime.RuntimeSettings", return_value=m_runtime_settings)
	m_ldc.get_user.return_value = m_user
	m_ldc.rebind.return_value = expected_rebind_return
	m_ldap_connector.return_value.__enter__.return_value = m_ldc

	result = authenticate(**m_request_data)

	m_ldc.get_user.assert_called_once()
	m_ldc.connection.unbind.assert_called_once()
	m_ldc.rebind.assert_called_once_with(user_dn=m_user.dn, password=m_request_data["password"])
	assert result is None


def test_authenticate_success(
	mocker,
	m_runtime_settings,
	m_request_data,
	m_ldap_connector,
	m_ldc,
	m_user,
	m_encrypted_password,
):
	"""Test successful authentication and user update."""
	mocker.patch("core.config.runtime.RuntimeSettings", return_value=m_runtime_settings)
	m_ldc.get_user.return_value = m_user
	m_ldc.rebind.return_value = True
	m_ldap_connector.return_value.__enter__.return_value = m_ldc

	m_aes_encrypt = mocker.patch(
		"core.ldap.connector.aes_encrypt", return_value=m_encrypted_password
	)
	m_setattr = mocker.patch("core.ldap.connector.setattr")
	m_update_last_login = mocker.patch("core.ldap.connector.update_last_login")

	result = authenticate(**m_request_data)

	# Assertions
	m_ldc.get_user.assert_called_once()
	m_ldc.connection.unbind.assert_called_once()
	m_ldc.rebind.assert_called_once_with(user_dn=m_user.dn, password=m_request_data["password"])
	m_aes_encrypt.assert_called_once_with(m_request_data["password"])
	for index, field in enumerate(USER_PASSWORD_FIELDS):
		m_setattr.assert_any_call(m_user, field, m_encrypted_password[index])
	assert m_user.user_type == USER_TYPE_LDAP
	m_update_last_login.assert_called_once_with(None, m_user)
	m_user.save.assert_called_once()
	assert result == m_user


def test_authenticate_superuser(mocker, m_runtime_settings, m_request_data):
	"""Test that authenticate returns None for the default superuser."""
	mocker.patch("core.config.runtime.RuntimeSettings", return_value=m_runtime_settings)
	m_request_data["username"] = DEFAULT_SUPERUSER_USERNAME

	result = authenticate(**m_request_data)

	assert result is None
