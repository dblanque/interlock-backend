import pytest
from pytest_mock import MockType, MockerFixture
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from inspect import getmembers, isroutine
from core.ldap import defaults as ldap_defaults
from core.ldap.connector import LDAPConnector
from typing import Protocol
from tests.test_core.type_hints import LDAPConnectorMock
from core.constants.attrs import LDAP_ATTR_DN
from ldap3 import Entry as LDAPEntry
from core.models.interlock_settings import (
	InterlockSetting,
	INTERLOCK_SETTING_ENABLE_LDAP,
	TYPE_BOOL,
)
from copy import deepcopy


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


@pytest.fixture(autouse=True)
def teardown_interlock_setting(db):
	yield
	InterlockSetting.objects.all().delete()


class RuntimeSettingsFactory(Protocol):
	def __call__(self, patch_path: str) -> RuntimeSettingsSingleton: ...


@pytest.fixture
def g_runtime_settings(mocker: MockerFixture) -> RuntimeSettingsFactory:
	def maker(patch_path: str = None):
		mock: MockType = mocker.MagicMock(spec=RuntimeSettingsSingleton)
		attributes = getmembers(
			RuntimeSettingsSingleton, lambda a: not (isroutine(a))
		)
		for setting_key, default_value in attributes:
			if setting_key.startswith("__") and setting_key.endswith("__"):
				continue
			setting_value = getattr(ldap_defaults, setting_key, None)
			setattr(mock, setting_key, deepcopy(setting_value))
		if patch_path:
			mocker.patch(patch_path, mock)
		return mock

	return maker


class ConnectorFactory(Protocol):
	def __call__(
		self,
		patch_path: str,
		use_spec=False,
		mock_enter: MockType = None,
		mock_exit: MockType = None,
	) -> LDAPConnectorMock: ...


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


class LDAPAttributeFactoryProtocol(Protocol):
	def __call__(self, attr: str, v) -> MockType: ...


@pytest.fixture
def fc_ldap_attr(mocker: MockerFixture) -> LDAPAttributeFactoryProtocol:
	def maker(attr: str, v):
		_SEQUENCE_TYPES = (
			list,
			tuple,
			set,
		)
		mock_attr = mocker.Mock(name=f"m_{attr}")
		if not type(v) in _SEQUENCE_TYPES:
			mock_attr.value = v
			mock_attr.values = [v]
			mock_attr.raw_values = [v]
		else:
			mock_attr.value = v[0] if len(v) < 2 else v
			mock_attr.values = v
			mock_attr.raw_values = v
		return mock_attr

	return maker


class LDAPEntryFactoryProtocol(Protocol):
	def __call__(self, spec: bool = False, **ldap_attrs): ...


@pytest.fixture
def fc_ldap_entry(
	mocker: MockerFixture,
	fc_ldap_attr: LDAPAttributeFactoryProtocol,
) -> LDAPEntryFactoryProtocol:
	def maker(**kwargs):
		if "spec" in kwargs:
			mock: LDAPEntry = mocker.MagicMock(spec=kwargs.pop("spec"))
		else:
			mock: LDAPEntry = mocker.MagicMock()
		mock.entry_attributes = []
		mock.entry_attributes_as_dict = {}
		mock.entry_raw_attributes = {}
		for k, v in kwargs.items():
			setattr(mock, k, fc_ldap_attr(k, v))
			mock.entry_attributes_as_dict[k] = [v]
			mock.entry_raw_attributes[k] = [v]
			mock.entry_attributes.append(k)

		# Set entry_dn
		distinguished_name = kwargs.pop(LDAP_ATTR_DN, None)
		if distinguished_name:
			mock.entry_dn = distinguished_name
		return mock

	return maker
