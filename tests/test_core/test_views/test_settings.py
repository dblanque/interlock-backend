########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture
################################################################################
from django.urls import reverse
from core.models.ldap_settings import LDAPPreset, LDAPSetting, LDAP_SETTING_MAP
from core.models.user import User
from typing import Protocol
from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework import status
from core.views.mixins.ldap_settings import SettingsViewMixin
from core.models.choices.log import (
	LOG_ACTION_READ,
	LOG_ACTION_UPDATE,
	LOG_CLASS_SET,
	LOG_TARGET_ALL,
)
from core.models.interlock_settings import (
	InterlockSetting,
	INTERLOCK_SETTING_MAP,
	INTERLOCK_SETTING_ENABLE_LDAP,
	INTERLOCK_SETTING_AES_KEY,
)

from core.constants.attrs.local import (
	LOCAL_ATTR_ID,
	LOCAL_ATTR_NAME,
	LOCAL_ATTR_LABEL,
	LOCAL_ATTR_ACTIVE,
	LOCAL_ATTR_VALUE,
)
from core.ldap import defaults
from core.constants.settings import *
from tests.test_core.test_views.conftest import UserFactory
from tests.test_core.conftest import ConnectorFactory
from interlock_backend.settings import DEFAULT_SUPERUSER_USERNAME
from interlock_backend.encrypt import aes_decrypt, aes_encrypt

class LdapPresetFactory(Protocol):
	def __call__(
		self,
		name="test_preset",
		label="Test Preset",
		active=False,
	) -> LDAPPreset: ...

@pytest.fixture(autouse=True)
def f_settings_mixin_patch(mocker: MockerFixture):
	mocker.patch.object(SettingsViewMixin, "resync_settings")

@pytest.fixture(autouse=True)
def f_ldap_connector(g_ldap_connector: ConnectorFactory):
	return g_ldap_connector(
		patch_path="core.views.mixins.ldap_settings.LDAPConnector"
	)

@pytest.fixture
def fc_ldap_preset() -> LdapPresetFactory:
	"""Fixture creating LDAP preset in the database"""
	def maker(**kwargs):
		return LDAPPreset.objects.create(
			name=kwargs.pop(LOCAL_ATTR_NAME, "test_preset"),
			label=kwargs.pop(LOCAL_ATTR_LABEL, "Test Preset"),
			active=kwargs.pop(LOCAL_ATTR_ACTIVE, False),
		)
	return maker

@pytest.fixture
def f_default_ilck_settings():
	from core.setup.interlock_setting import create_default_interlock_settings
	create_default_interlock_settings()

@pytest.fixture
def f_default_superadmin(user_factory: UserFactory):
	return user_factory(username=DEFAULT_SUPERUSER_USERNAME, email=None)

@pytest.fixture
def f_log_mixin(mocker: MockerFixture):
	return mocker.patch("core.views.ldap_settings.DBLogMixin")

class TestList:
	endpoint = reverse("settings-list")

	def test_success(
		self,
		mocker: MockerFixture,
		fc_ldap_preset: LdapPresetFactory,
		admin_user_client: APIClient,
		admin_user: User,
		f_log_mixin,
	):
		f_preset_01 = fc_ldap_preset(
			name="test_preset_01", label="Test Preset 01", active=True)
		f_preset_02 = fc_ldap_preset(
			name="test_preset_02", label="Test Preset 02")
		
		response: Response = admin_user_client.get(self.endpoint)
		response_data: dict = response.data

		f_log_mixin.log.assert_called_once_with(
			user=admin_user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_SET,
			log_target=LOG_TARGET_ALL,
		)
		assert response.status_code == status.HTTP_200_OK
		assert response_data["presets"][0]["id"] == f_preset_01.id
		assert response_data["presets"][1]["id"] == f_preset_02.id
		assert response_data["active_preset"] == f_preset_01.id

class TestFetch:
	endpoint = reverse("settings-fetch", args=(1,))

	@pytest.mark.parametrize(
		"superadmin_enabled",
		(
			True,
			False,
		),
		ids=[
			"With local superadmin",
			"Without local superadmin",
		]
	)
	def test_success(
		self,
		mocker: MockerFixture,
		fc_ldap_preset: LdapPresetFactory,
		f_default_ilck_settings,
		f_default_superadmin: User,
		superadmin_enabled: bool,
		admin_user_client: APIClient,
		admin_user: User,
		f_log_mixin,
	):
		if f_default_superadmin.deleted != (not superadmin_enabled):
			f_default_superadmin.deleted = (not f_default_superadmin.deleted)
			f_default_superadmin.save()
			f_default_superadmin.refresh_from_db()

		f_preset_01 = fc_ldap_preset(
			name="test_preset_01", label="Test Preset 01", active=True)
		f_preset_02 = fc_ldap_preset(
			name="test_preset_02", label="Test Preset 02")

		response: Response = admin_user_client.get(self.endpoint)
		response_data: dict = response.data

		f_log_mixin.log.assert_called_once_with(
			user=admin_user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_SET,
			log_target=LOG_TARGET_ALL,
		)
		assert response.status_code == status.HTTP_200_OK
		assert "settings" in response_data
		assert "local" in response_data["settings"]
		assert "ldap" in response_data["settings"]
		assert response_data["settings"]["ldap"]["DEFAULT_ADMIN_ENABLED"] == superadmin_enabled
		assert isinstance(response_data["settings"]["local"], dict)
		assert isinstance(response_data["settings"]["ldap"], dict)

class TestPresetCreate:
	endpoint = reverse("settings-preset-create")

	@pytest.mark.parametrize(
		"label, expected_name",
		(
			("Test Preset", "test_preset"),
			("Test-Preset", "test_preset"),
			("Test-Preset 01", "test_preset_01"),
		),
	)
	def test_success(
		self,
		admin_user_client: APIClient,
		label: str,
		expected_name: str,
	):
		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				LOCAL_ATTR_LABEL: label
			},
			format="json",
		)
		assert response.status_code == status.HTTP_200_OK

		ldap_preset = LDAPPreset.objects.get(name=expected_name)
		assert ldap_preset.name == expected_name
		assert ldap_preset.label == label

	@pytest.mark.parametrize(
		LOCAL_ATTR_LABEL,
		(
			"@($&ASBL)",
			False,
			{"a":"dict"},
			["a","list"],
		),
	)
	def test_raises_serializer_exc(
		self,
		admin_user_client: APIClient,
		label: str,
	):
		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				LOCAL_ATTR_LABEL: label
			},
			format="json",
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert LDAPPreset.objects.count() == 0

class TestPresetDelete:
	endpoint = reverse("settings-preset-delete")

	def test_success(
		self,
		admin_user_client: APIClient,
		fc_ldap_preset: LdapPresetFactory,
	):
		m_preset_name = "test_preset_delete"
		m_preset = fc_ldap_preset(
			name=m_preset_name,
			label="Test Preset Delete",
		)
		m_preset.save()

		response: Response = admin_user_client.post(
			self.endpoint,
			data={LOCAL_ATTR_ID: m_preset.id},
		)

		assert response.status_code == status.HTTP_200_OK
		assert LDAPPreset.objects.filter(name=m_preset_name).count() == 0

class TestPresetEnable:
	endpoint = reverse("settings-preset-enable")

	def test_success(
		self,
		admin_user_client: APIClient,
		fc_ldap_preset: LdapPresetFactory,
	):
		m_preset_name = "test_preset_enable"
		m_preset = fc_ldap_preset(
			name=m_preset_name,
			label="Test Preset Enable",
		)
		m_preset.save()

		response: Response = admin_user_client.post(
			self.endpoint,
			data={LOCAL_ATTR_ID: m_preset.id},
		)

		assert response.status_code == status.HTTP_200_OK
		m_preset.refresh_from_db()
		assert m_preset.active
		assert LDAPPreset.objects.filter(active=True).count() == 1
		assert LDAPPreset.objects.get(active=True) == m_preset

class TestPresetRename:
	endpoint = reverse("settings-preset-rename")

	def test_success(
		self,
		admin_user_client: APIClient,
		fc_ldap_preset: LdapPresetFactory,
	):
		m_preset_name = "test_preset_rename"
		m_preset = fc_ldap_preset(
			name=m_preset_name,
			label="Test Preset Rename",
		)
		m_preset.save()

		response: Response = admin_user_client.post(
			self.endpoint,
			data={LOCAL_ATTR_ID: m_preset.id, LOCAL_ATTR_LABEL: "New Name"}
		)
		assert response.status_code == status.HTTP_200_OK

		m_preset.refresh_from_db()
		assert m_preset.name == "new_name"
		assert m_preset.label == "New Name"

class TestSave:
	endpoint = reverse("settings-save")

	def test_raises_no_preset(self, admin_user_client: APIClient):
		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				"preset": {},
				"settings":{},
			},
			format="json"
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("code") == "data_key_missing"
		assert response.data.get("key") == "data.preset.id"

	def test_raises_preset_not_exists(self, admin_user_client: APIClient):
		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				"preset": {"id": 999},
				"settings":{
					"local": {},
					"ldap": {},
				},
			},
			format="json"
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("code") == "setting_preset_not_exists"

	@pytest.mark.django_db
	@pytest.mark.parametrize(
		"setting_key, setting_value, test_removal_on_default",
		(
			# Adding overrides
			(K_LDAP_LOG_CREATE, (not defaults.LDAP_LOG_CREATE), False),
			(K_LDAP_LOG_READ, (not defaults.LDAP_LOG_READ), False),
			(K_LDAP_LOG_UPDATE, (not defaults.LDAP_LOG_UPDATE), False),
			(K_LDAP_LOG_DELETE, (not defaults.LDAP_LOG_DELETE), False),
			(K_LDAP_LOG_OPEN_CONNECTION, (not defaults.LDAP_LOG_OPEN_CONNECTION), False),
			(K_LDAP_LOG_CLOSE_CONNECTION, (not defaults.LDAP_LOG_CLOSE_CONNECTION), False),
			(K_LDAP_LOG_LOGIN, (not defaults.LDAP_LOG_LOGIN), False),
			(K_LDAP_LOG_LOGOUT, (not defaults.LDAP_LOG_LOGOUT), False),
			(K_LDAP_DNS_LEGACY, (not defaults.LDAP_DNS_LEGACY), False),
			(K_LDAP_AUTH_CONNECTION_USER_DN, "mock_dn", False),
			(K_LDAP_AUTH_CONNECTION_USERNAME, "mock_user", False),
			(K_LDAP_AUTH_CONNECTION_PASSWORD, "mock_password", False),
			(K_EXCLUDE_COMPUTER_ACCOUNTS, (not defaults.EXCLUDE_COMPUTER_ACCOUNTS), False),
			(K_ADMIN_GROUP_TO_SEARCH, "mock_group_to_search", False),
			(K_LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN, "EXMPLORG", False),
			(K_LDAP_DOMAIN, "example.org", False),
			(K_LDAP_AUTH_URL, ["ldaps://127.1.1.1"], False),
			(K_LDAP_FIELD_MAP, {"some":"dict"}, False),

			# Deleting overrides
			(K_LDAP_LOG_CREATE, (not defaults.LDAP_LOG_CREATE), True),
			(K_LDAP_LOG_READ, (not defaults.LDAP_LOG_READ), True),
			(K_LDAP_LOG_UPDATE, (not defaults.LDAP_LOG_UPDATE), True),
			(K_LDAP_LOG_DELETE, (not defaults.LDAP_LOG_DELETE), True),
			(K_LDAP_LOG_OPEN_CONNECTION, (not defaults.LDAP_LOG_OPEN_CONNECTION), True),
			(K_LDAP_LOG_CLOSE_CONNECTION, (not defaults.LDAP_LOG_CLOSE_CONNECTION), True),
			(K_LDAP_LOG_LOGIN, (not defaults.LDAP_LOG_LOGIN), True),
			(K_LDAP_LOG_LOGOUT, (not defaults.LDAP_LOG_LOGOUT), True),
			(K_LDAP_DNS_LEGACY, (not defaults.LDAP_DNS_LEGACY), True),
			(K_LDAP_AUTH_CONNECTION_USER_DN, "mock_dn", True),
			(K_LDAP_AUTH_CONNECTION_USERNAME, "mock_user", True),
			(K_LDAP_AUTH_CONNECTION_PASSWORD, "mock_password", True),
			(K_EXCLUDE_COMPUTER_ACCOUNTS, (not defaults.EXCLUDE_COMPUTER_ACCOUNTS), True),
			(K_ADMIN_GROUP_TO_SEARCH, "mock_group_to_search", True),
			(K_LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN, "EXMPLORG", True),
			(K_LDAP_DOMAIN, "example.org", True),
			(K_LDAP_AUTH_URL, ["ldaps://127.1.1.1"], True),
			(K_LDAP_FIELD_MAP, {"some":"dict"}, False),
		),
	)
	def test_success_adding_ldap_override(
		self,
		setting_key: str,
		setting_value,
		test_removal_on_default: bool,
		admin_user_client: APIClient,
		fc_ldap_preset: LdapPresetFactory,
	):
		ldap_preset = fc_ldap_preset(active=True)
		if test_removal_on_default:
			if setting_key == K_LDAP_AUTH_CONNECTION_PASSWORD:
				_v = aes_encrypt(setting_value)
			else:
				_v = setting_value
			_si = LDAPSetting(
				name=setting_key,
				value=_v,
				type=LDAP_SETTING_MAP[setting_key],
				preset_id=ldap_preset.id,
			)
			_si.save()

		m_value = None
		if test_removal_on_default:
			assert setting_key in dir(defaults)
			m_value = getattr(defaults, setting_key)
		else:
			m_value = setting_value

		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				"preset": {"id": ldap_preset.id},
				"settings":{
					"local": {},
					"ldap": {setting_key: {LOCAL_ATTR_VALUE: m_value}},
				},
			},
			format="json",
		)
		assert response.status_code == status.HTTP_200_OK

		if test_removal_on_default:
			assert not LDAPSetting.objects.filter(
				name=setting_key,
				preset_id=ldap_preset.id,
			).exists()
		else:
			setting_instance = LDAPSetting.objects.get(
				name=setting_key,
				preset_id=ldap_preset.id,
			)
			if setting_key == K_LDAP_AUTH_CONNECTION_PASSWORD:
				assert aes_decrypt(*setting_instance.value) == setting_value
			else:
				assert setting_instance.value == setting_value

	@pytest.mark.django_db
	@pytest.mark.parametrize(
		"setting_key, setting_value",
		(
			# Booleans with wrong types
			(K_LDAP_LOG_CREATE, "string",),
			(K_LDAP_LOG_READ, "string",),
			(K_LDAP_LOG_UPDATE, "string",),
			(K_LDAP_LOG_DELETE, "string",),
			(K_LDAP_LOG_OPEN_CONNECTION, "string",),
			(K_LDAP_LOG_CLOSE_CONNECTION, "string",),
			(K_LDAP_LOG_LOGIN, "string",),
			(K_LDAP_LOG_LOGOUT, "string",),
			(K_LDAP_DNS_LEGACY, "string",),
			(K_EXCLUDE_COMPUTER_ACCOUNTS, "string",),
			# Strings with wrong types
			(K_LDAP_AUTH_CONNECTION_USER_DN, False),
			(K_LDAP_AUTH_CONNECTION_USERNAME, None,),
			(K_LDAP_AUTH_CONNECTION_PASSWORD, ["list"],),
			(K_ADMIN_GROUP_TO_SEARCH, {"a":"dict"},),
			# List with wrong type
			(K_LDAP_AUTH_URL, "ldaps://127.1.1.1",),
		),
	)
	def test_raises_serializer_error(
		self,
		setting_key: str,
		setting_value,
		admin_user_client: APIClient,
		fc_ldap_preset: LdapPresetFactory,
	):
		ldap_preset = fc_ldap_preset(active=True)
		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				"preset": {"id": ldap_preset.id},
				"settings":{
					"local": {},
					"ldap": {setting_key: {LOCAL_ATTR_VALUE: setting_value}},
				},
			},
			format="json",
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert not LDAPSetting.objects.filter(
			name=setting_key,
			preset_id=ldap_preset.id,
		).exists()

	@pytest.mark.django_db
	@pytest.mark.parametrize(
		"setting_key, setting_value",
		(
			(INTERLOCK_SETTING_ENABLE_LDAP, True),
			(INTERLOCK_SETTING_ENABLE_LDAP, False),
		),
	)
	def test_success_adding_local_override(
		self,
		setting_key: str,
		setting_value,
		admin_user_client: APIClient,
		fc_ldap_preset: LdapPresetFactory,
		f_settings_mixin_patch,
	):
		ldap_preset = fc_ldap_preset(active=True)

		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				"preset": {"id": ldap_preset.id},
				"settings":{
					"local": {setting_key: {LOCAL_ATTR_VALUE: setting_value}},
					"ldap": {},
				},
			},
			format="json",
		)
		assert response.status_code == status.HTTP_200_OK

		setting_instance = InterlockSetting.objects.get(name=setting_key)
		SettingsViewMixin.resync_settings.assert_called_once()
		assert setting_instance.value == setting_value

	@pytest.mark.parametrize(
		"m_status, m_password",
		(
			(True, "mock_password_change"),
			(False, None),
		),
	)
	def test_local_admin_status_change(
		self,
		m_status: bool,
		m_password: str,
		admin_user_client: APIClient,
		admin_user: User,
		fc_ldap_preset: LdapPresetFactory,
		f_default_superadmin: User,
		f_log_mixin,
	):
		ldap_preset = fc_ldap_preset(active=True)

		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				"preset": {"id": ldap_preset.id},
				"settings":{
					"DEFAULT_ADMIN_ENABLED": m_status,
					"DEFAULT_ADMIN_PWD": m_password,
					"local": {},
					"ldap": {},
				},
			},
			format="json",
		)

		assert response.status_code == status.HTTP_200_OK
		f_default_superadmin.refresh_from_db()
		if m_password is not None:
			assert f_default_superadmin.check_password(m_password)
		assert f_default_superadmin.deleted == (not m_status)
		f_log_mixin.log.assert_called_once_with(
			user=admin_user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_SET,
		)
