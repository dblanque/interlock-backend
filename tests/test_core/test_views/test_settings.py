########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType
################################################################################
from django.urls import reverse
from core.models.ldap_settings import LDAPPreset
from core.models.user import User
from typing import Protocol
from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework import status
from core.models.choices.log import (
	LOG_ACTION_READ,
	LOG_CLASS_SET,
	LOG_TARGET_ALL,
)
from core.constants.attrs.local import (
	LOCAL_ATTR_ID,
	LOCAL_ATTR_NAME,
	LOCAL_ATTR_LABEL,
	LOCAL_ATTR_ACTIVE,
)
from tests.test_core.test_views.conftest import UserFactory
from interlock_backend.settings import DEFAULT_SUPERUSER_USERNAME

class LdapPresetFactory(Protocol):
	def __call__(
		self,
		name="test_preset",
		label="Test Preset",
		active=False,
	) -> LDAPPreset: ...

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

class TestList:
	endpoint = reverse("settings-list")

	def test_success(
		self,
		mocker: MockerFixture,
		fc_ldap_preset: LdapPresetFactory,
		admin_user_client: APIClient,
		admin_user: User,
	):
		m_log_mixin = mocker.patch("core.views.ldap_settings.DBLogMixin")
		f_preset_01 = fc_ldap_preset(
			name="test_preset_01", label="Test Preset 01", active=True)
		f_preset_02 = fc_ldap_preset(
			name="test_preset_02", label="Test Preset 02")
		
		response: Response = admin_user_client.get(self.endpoint)
		response_data: dict = response.data

		m_log_mixin.log.assert_called_once_with(
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
	):
		if f_default_superadmin.deleted != (not superadmin_enabled):
			f_default_superadmin.deleted = (not f_default_superadmin.deleted)
			f_default_superadmin.save()
			f_default_superadmin.refresh_from_db()

		m_log_mixin = mocker.patch("core.views.ldap_settings.DBLogMixin")
		f_preset_01 = fc_ldap_preset(
			name="test_preset_01", label="Test Preset 01", active=True)
		f_preset_02 = fc_ldap_preset(
			name="test_preset_02", label="Test Preset 02")

		response: Response = admin_user_client.get(self.endpoint)
		response_data: dict = response.data

		m_log_mixin.log.assert_called_once_with(
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
