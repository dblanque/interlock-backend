import pytest
from unittest.mock import MagicMock, Mock
from core.models.ldap_settings import LDAP_SETTING_MAP
from core.ldap import defaults as ldap_defaults

@pytest.fixture
def m_connection(mocker) -> MagicMock:
	return mocker.MagicMock()

@pytest.fixture
def m_runtime_settings(mocker) -> MagicMock:
	mock = mocker.MagicMock()
	for setting_key, setting_type in LDAP_SETTING_MAP.items():
		setting_value = getattr(ldap_defaults, setting_key)
		setattr(mock, setting_key, setting_value)
	return mock
