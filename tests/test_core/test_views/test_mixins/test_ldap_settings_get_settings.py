########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType
################################################################################
from core.constants.attrs.local import (
	LOCAL_ATTR_NAME,
	LOCAL_ATTR_TYPE,
	LOCAL_ATTR_VALUE,
	LOCAL_ATTR_PRESET,
)
from core.constants.settings import *
from core.models.ldap_settings import LDAP_SETTING_MAP
from core.ldap import defaults
from interlock_backend.settings import DEFAULT_SUPERUSER_USERNAME
from enum import Enum
from core.setup.user import create_default_superuser
from core.models.user import User
from core.views.mixins.ldap_settings import SettingsViewMixin
from core.models.ldap_settings import LDAPSetting, LDAPPreset
from core.views.mixins.ldap_settings import SettingsViewMixin
from interlock_backend.encrypt import aes_encrypt
from typing import Protocol, Generator
import ssl

@pytest.fixture
def f_default_superuser():
	create_default_superuser()
	_user: User = User.objects.get(username=DEFAULT_SUPERUSER_USERNAME)
	yield _user
	_user.delete_permanently()

@pytest.fixture(autouse=True)
def f_create_default_preset(django_db_blocker):
	with django_db_blocker.unblock():
		_mixin = SettingsViewMixin()
		return _mixin.create_default_preset()

@pytest.fixture
def f_default_preset():
	return LDAPPreset.objects.get(active=True)

class SettingFactoryProtocol(Protocol):
	def __call__(self, setting_key: str, setting_value) -> LDAPSetting: ...


@pytest.fixture
def fc_setting_override(f_default_preset) -> Generator[SettingFactoryProtocol, None, None]:
	def maker(setting_key: str, setting_value):
		assert f_default_preset
		_override = LDAPSetting.objects.create(**{
			LOCAL_ATTR_NAME: setting_key,
			LOCAL_ATTR_TYPE: LDAP_SETTING_MAP[setting_key],
			LOCAL_ATTR_PRESET: f_default_preset,
			LOCAL_ATTR_VALUE: setting_value
		})
		return _override
	return maker


@pytest.fixture
def f_password_override(fc_setting_override: SettingFactoryProtocol):
	return fc_setting_override(
		setting_key=K_LDAP_AUTH_CONNECTION_PASSWORD,
		setting_value=aes_encrypt("mock_password")
	)

class TestGetSettings:
	@pytest.mark.django_db
	def test_all_defaults(self):
		_settings = SettingsViewMixin().get_ldap_settings()
		_expected_keys = list(LDAP_SETTING_MAP.keys()) + ["DEFAULT_ADMIN_ENABLED"]
		assert isinstance(_settings, dict)
		assert set(_settings.keys()) == set(_expected_keys)
		assert not _settings.get("DEFAULT_ADMIN_ENABLED")
		for _key in LDAP_SETTING_MAP.keys():
			_default_v = getattr(defaults, _key)
			if isinstance(_default_v, Enum):
				_default_v = _default_v.name
			assert _settings.get(_key).get(LOCAL_ATTR_VALUE) == _default_v

	@pytest.mark.django_db(transaction=True)
	def test_with_default_superuser(self, f_default_superuser: User):
		_settings = SettingsViewMixin().get_ldap_settings()
		assert _settings.get("DEFAULT_ADMIN_ENABLED")

	@pytest.mark.django_db(transaction=True)
	def test_with_logic_delete_default_superuser(
		self,
		f_default_superuser: User
	):
		f_default_superuser.delete()
		f_default_superuser.refresh_from_db()
		_settings = SettingsViewMixin().get_ldap_settings()
		assert not _settings.get("DEFAULT_ADMIN_ENABLED")

	@pytest.mark.django_db(transaction=True)
	def test_with_connection_password(
		self,
		f_password_override: LDAPSetting,
		f_default_preset: LDAPPreset,
	):
		_settings = SettingsViewMixin().get_ldap_settings(f_default_preset.id)
		assert _settings.get(K_LDAP_AUTH_CONNECTION_PASSWORD)\
			.get(LOCAL_ATTR_VALUE) == "mock_password"

	@pytest.mark.django_db(transaction=True)
	def test_with_non_decryptable_connection_password(
		self,
		mocker: MockerFixture,
		f_password_override: LDAPSetting,
		f_default_preset: LDAPPreset,
	):
		m_logger = mocker.patch("core.views.mixins.ldap_settings.logger")
		mocker.patch(
			"core.views.mixins.ldap_settings.aes_decrypt",
			side_effect=Exception
		)
		_settings = SettingsViewMixin().get_ldap_settings(f_default_preset.id)
		assert _settings.get(K_LDAP_AUTH_CONNECTION_PASSWORD)\
			.get(LOCAL_ATTR_VALUE) == ""
		m_logger.error.assert_called_once_with("Could not decrypt password")

	@pytest.mark.parametrize(
		"setting_key, setting_value",
		(
			(K_LDAP_AUTH_URL, ["ldap://127.0.99.1:389"]),
			(K_LDAP_DOMAIN, "example.org"),
			(K_LDAP_LOG_MAX, 50),
			(K_LDAP_LOG_READ, True),
			(K_LDAP_LOG_CREATE, False),
			(K_LDAP_LOG_UPDATE, False),
			(K_LDAP_LOG_DELETE, False),
			(K_LDAP_LOG_OPEN_CONNECTION, True),
			(K_LDAP_LOG_CLOSE_CONNECTION, True),
			(K_LDAP_LOG_LOGIN, True),
			(K_LDAP_LOG_LOGOUT, True),
			(K_LDAP_AUTH_USE_SSL, True),
			(K_LDAP_AUTH_USE_TLS, True),
			(K_LDAP_AUTH_TLS_VERSION, ssl.PROTOCOL_TLSv1_1.name),
			(K_LDAP_AUTH_SEARCH_BASE, "dc=example,dc=org"),
			(K_LDAP_DNS_LEGACY, True),
			(K_LDAP_AUTH_OBJECT_CLASS, "user"),
			(K_EXCLUDE_COMPUTER_ACCOUNTS, False),
			(K_LDAP_FIELD_MAP, {"mock":"dict"}),
			(K_LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN, "EXMPLORG"),
			(K_LDAP_AUTH_CONNECTION_USER_DN, "CN=TestAdmin,CN=Users,DC=example,DC=org"),
			(K_LDAP_AUTH_CONNECTION_USERNAME, "TestAdmin"),
			(K_LDAP_AUTH_CONNECT_TIMEOUT, 15),
			(K_LDAP_AUTH_RECEIVE_TIMEOUT, 15),
			(K_ADMIN_GROUP_TO_SEARCH, "CN=Administrators,CN=Builtin,DC=example,DC=org"),
		),
	)
	@pytest.mark.django_db(transaction=True)
	def test_overrides(
		self,
		setting_key,
		setting_value,
		fc_setting_override: SettingFactoryProtocol,
		f_default_preset: LDAPPreset,
	):
		_override = fc_setting_override(setting_key, setting_value)
		_settings = SettingsViewMixin().get_ldap_settings(preset_id=f_default_preset.id)
		_v = _settings.get(setting_key).get(LOCAL_ATTR_VALUE)
		assert _v == _override.value
