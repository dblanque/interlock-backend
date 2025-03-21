import pytest
from pytest_mock import MockType
from interlock_backend.test_settings import DEFAULT_SUPERUSER_USERNAME
from core.models.user import USER_TYPE_LDAP, USER_PASSWORD_FIELDS
from core.ldap.connector import authenticate


@pytest.fixture
def f_request_data() -> dict:
	return {"username": "testuser", "password": "somepassword"}


@pytest.fixture
def f_encrypted_password() -> tuple:
	return ("encrypted_aes_key", "ciphertext", "nonce", "tag")


@pytest.fixture
def f_ldap_connector(mocker) -> MockType:
	"""Fixture to mock LDAPConnector and its context manager."""
	m_connector = mocker.patch("core.ldap.connector.LDAPConnector", return_value=mocker.MagicMock())
	return m_connector


@pytest.fixture
def f_ldc(mocker, f_connection) -> MockType:
	"""Fixture to mock the LDAPConnector context manager (ldc)."""
	m_ldc = mocker.Mock()
	m_ldc.connection = f_connection
	return m_ldc


@pytest.fixture
def f_connection(mocker, f_connection) -> MockType:
	"""Fixture to mock the LDAP connection."""
	f_connection.unbind = mocker.Mock(name="m_connection_unbind")
	f_connection.rebind = mocker.Mock(name="m_connection_rebind")
	return f_connection


def test_authenticate_connection_bad_kwargs(
	mocker, f_runtime_settings, f_request_data, f_ldap_connector
):
	"""Test that authenticate returns None when the LDAP connection is None."""
	mocker.patch("core.config.runtime.RuntimeSettings", f_runtime_settings)
	f_ldap_connector.return_value.__enter__.return_value.connection = None

	f_request_data.pop("password")
	assert authenticate(**f_request_data) is None

def test_authenticate_connection_is_none(
	mocker, f_runtime_settings, f_request_data, f_ldap_connector
):
	"""Test that authenticate returns None when the LDAP connection is None."""
	mocker.patch("core.config.runtime.RuntimeSettings", f_runtime_settings)
	f_ldap_connector.return_value.__enter__.return_value.connection = None

	assert authenticate(**f_request_data) is None


def test_authenticate_get_user_is_none(
	mocker, f_runtime_settings, f_request_data, f_ldap_connector, f_ldc
):
	"""Test that authenticate returns None when get_user returns None."""
	mocker.patch("core.config.runtime.RuntimeSettings", f_runtime_settings)
	f_ldc.get_user.return_value = None
	f_ldap_connector.return_value.__enter__.return_value = f_ldc

	result = authenticate(**f_request_data)

	f_ldc.get_user.assert_called_once()
	f_ldc.connection.unbind.assert_called_once()
	assert result is None


@pytest.mark.parametrize("expected_rebind_return", [False, None])
def test_authenticate_rebind_is_not_truthy(
	expected_rebind_return,
	mocker,
	f_runtime_settings,
	f_request_data,
	f_ldap_connector,
	f_ldc,
	f_user,
):
	"""Test that authenticate returns None when rebind returns a non-truthy value."""
	mocker.patch("core.config.runtime.RuntimeSettings", f_runtime_settings)
	f_ldc.get_user.return_value = f_user
	f_ldc.rebind.return_value = expected_rebind_return
	f_ldap_connector.return_value.__enter__.return_value = f_ldc

	result = authenticate(**f_request_data)

	f_ldc.get_user.assert_called_once()
	f_ldc.connection.unbind.assert_called_once()
	f_ldc.rebind.assert_called_once_with(user_dn=f_user.dn, password=f_request_data["password"])
	assert result is None


def test_authenticate_success(
	mocker,
	f_runtime_settings,
	f_request_data,
	f_ldap_connector,
	f_ldc,
	f_user,
	f_encrypted_password,
):
	"""Test successful authentication and user update."""
	mocker.patch("core.config.runtime.RuntimeSettings", f_runtime_settings)
	f_ldc.get_user.return_value = f_user
	f_ldc.rebind.return_value = True
	f_ldap_connector.return_value.__enter__.return_value = f_ldc

	m_aes_encrypt = mocker.patch(
		"core.ldap.connector.aes_encrypt", return_value=f_encrypted_password
	)
	m_setattr = mocker.patch("core.ldap.connector.setattr")
	m_update_last_login = mocker.patch("core.ldap.connector.update_last_login")

	result = authenticate(**f_request_data)

	# Assertions
	f_ldc.get_user.assert_called_once()
	f_ldc.connection.unbind.assert_called_once()
	f_ldc.rebind.assert_called_once_with(user_dn=f_user.dn, password=f_request_data["password"])
	m_aes_encrypt.assert_called_once_with(f_request_data["password"])
	for index, field in enumerate(USER_PASSWORD_FIELDS):
		m_setattr.assert_any_call(f_user, field, f_encrypted_password[index])
	assert f_user.user_type == USER_TYPE_LDAP
	m_update_last_login.assert_called_once_with(None, f_user)
	f_user.save.assert_called_once()
	assert result == f_user


def test_authenticate_superuser(mocker, f_runtime_settings, f_request_data):
	"""Test that authenticate returns None for the default superuser."""
	mocker.patch("core.config.runtime.RuntimeSettings", f_runtime_settings)
	f_request_data["username"] = DEFAULT_SUPERUSER_USERNAME

	result = authenticate(**f_request_data)

	assert result is None
