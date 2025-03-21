import pytest
from pytest_mock import MockType
from core.models.ldap_settings import LDAP_SETTING_MAP
from ldap3 import ServerPool, Connection
from core.models.ldap_settings_runtime import RunningSettingsClass
from core.models.user import USER_TYPE_LDAP, User
from core.ldap import defaults as ldap_defaults
from typing import Union


@pytest.fixture
def f_ldap_connection(mocker) -> MockType:
	return mocker.MagicMock(spec=Connection)

@pytest.fixture
def f_server_pool(mocker) -> MockType:
	return mocker.MagicMock(spec=ServerPool)

@pytest.fixture
def f_runtime_settings(mocker) -> Union[MockType, RunningSettingsClass]:
	mock = mocker.MagicMock()
	for setting_key, setting_type in LDAP_SETTING_MAP.items():
		setting_value = getattr(ldap_defaults, setting_key)
		setattr(mock, setting_key, setting_value)
	return mock


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
	m_user.encryptedPassword = ("encrypted_aes_key", "ciphertext", "nonce", "tag",)
	return m_user