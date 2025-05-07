import pytest
from pytest_mock import MockType
from ldap3 import Server, ServerPool, Connection, Tls
from core.models.user import USER_TYPE_LDAP, User
from core.ldap import defaults as ldap_defaults
from typing import Union


@pytest.fixture
def f_runtime_settings(g_runtime_settings):
	return g_runtime_settings


@pytest.fixture
def f_ldap_connection(mocker) -> MockType:
	return mocker.MagicMock(spec=Connection)


@pytest.fixture
def f_server_pool(mocker) -> MockType:
	return mocker.MagicMock(spec=ServerPool)


@pytest.fixture
def f_server(mocker) -> MockType:
	return mocker.MagicMock(spec=Server)


@pytest.fixture
def f_tls(mocker) -> MockType:
	return mocker.MagicMock(spec=Tls)


@pytest.fixture
def f_user_dn():
	return f"cn=testuser,{ldap_defaults.LDAP_AUTH_SEARCH_BASE}"


@pytest.fixture
def f_admin_dn():
	return f"CN=Administrator,CN=Users,{ldap_defaults.LDAP_AUTH_SEARCH_BASE}".lower()


# Fixtures for common test data
@pytest.fixture
def f_user(mocker, f_user_dn) -> Union[MockType, User]:
	m_user = mocker.MagicMock(name="m_user")
	m_user.id = 1
	m_user.save = mocker.Mock(name="m_user_save")
	m_user.username = "testuser"
	m_user.user_type = USER_TYPE_LDAP
	m_user.dn = f_user_dn
	m_user.encrypted_password = (
		"encrypted_aes_key",
		"ciphertext",
		"nonce",
		"tag",
	)
	return m_user
