import pytest
from pytest_mock import MockType, MockerFixture
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from inspect import getmembers, isroutine
from core.ldap import defaults as ldap_defaults
from core.ldap.connector import LDAPConnector
from typing import Protocol
from core.models.interlock_settings import (
	InterlockSetting,
	INTERLOCK_SETTING_ENABLE_LDAP,
	TYPE_BOOL,
)

@pytest.fixture
def g_interlock_ldap_enabled(db):
	# Fake LDAP Enabled
	InterlockSetting.objects.create(
		name=INTERLOCK_SETTING_ENABLE_LDAP, type=TYPE_BOOL, value=True
	)

@pytest.fixture
def g_interlock_ldap_disabled(db):
	# Fake LDAP Disabled
	InterlockSetting.objects.create(
		name=INTERLOCK_SETTING_ENABLE_LDAP, type=TYPE_BOOL, value=False
	)

class RuntimeSettingsFactory(Protocol):
	def __call__(self) -> RuntimeSettingsSingleton: ...


@pytest.fixture
def g_runtime_settings(mocker: MockerFixture) -> RuntimeSettingsFactory:
	mock: MockType = mocker.MagicMock(spec=RuntimeSettingsSingleton)
	attributes = getmembers(
		RuntimeSettingsSingleton, lambda a: not (isroutine(a))
	)
	for setting_key, default_value in attributes:
		if setting_key.startswith("__") and setting_key.endswith("__"):
			continue
		setting_value = getattr(ldap_defaults, setting_key, None)
		setattr(mock, setting_key, setting_value)
	return mock


class ConnectorFactory(Protocol):
	def __call__(
		self,
		patch_path: str,
		use_spec=False,
		mock_enter: MockType = None,
		mock_exit: MockType = None,
	) -> LDAPConnector | MockType: ...


@pytest.fixture
def g_ldap_connector(mocker: MockerFixture) -> ConnectorFactory:
	def fake_exit(self, exc_type, exc_value, traceback) -> None:
		if exc_value:
			raise exc_value

	def maker(
		patch_path: str,
		use_spec=False,
		mock_enter: MockType = None,
		mock_exit: MockType = None,
	):
		"""Fixture to mock LDAPConnector and its context manager."""
		if use_spec:
			m_connector = mocker.Mock(name="m_connector", spec=LDAPConnector)
		else:
			m_connector = mocker.Mock(name="m_connector")

		m_connector.connection = mocker.Mock(name="m_connection")
		default_m_enter = mocker.Mock(return_value=m_connector)

		# Mock Context Manager
		m_cxt_manager = mocker.Mock()
		m_cxt_manager.__enter__ = mock_enter if mock_enter else default_m_enter
		m_cxt_manager.__exit__ = fake_exit if not mock_exit else mock_exit

		# Patch Connector
		m_connector_cls = mocker.patch(patch_path, return_value=m_cxt_manager)
		m_connector.cxt_manager = m_cxt_manager
		m_connector.cls_mock = m_connector_cls
		return m_connector

	return maker
