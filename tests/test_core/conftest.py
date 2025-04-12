import pytest
from typing import Union
from pytest_mock import MockType
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from inspect import getmembers, isroutine
from core.ldap import defaults as ldap_defaults


@pytest.fixture
def g_runtime_settings(mocker) -> Union[MockType, RuntimeSettingsSingleton]:
	mock: MockType = mocker.MagicMock(spec=RuntimeSettingsSingleton)
	attributes = getmembers(RuntimeSettingsSingleton, lambda a: not (isroutine(a)))
	for setting_key, default_value in attributes:
		if setting_key.startswith("__") and setting_key.endswith("__"):
			continue
		setting_value = getattr(ldap_defaults, setting_key, None)
		setattr(mock, setting_key, setting_value)
	return mock
