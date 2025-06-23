########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture
################################################################################

### Models
from core.models.ldap_settings import LDAPPreset, LDAPSetting
from core.models.user import User
from core.models.choices.log import (
	LOG_ACTION_READ,
	LOG_ACTION_UPDATE,
	LOG_CLASS_SET,
	LOG_TARGET_ALL,
)
from core.models.types.settings import TYPE_LDAP_URI, TYPE_BOOL, TYPE_STRING

### Constants
from core.constants.attrs.local import (
	LOCAL_ATTR_ID,
	LOCAL_ATTR_NAME,
	LOCAL_ATTR_LABEL,
	LOCAL_ATTR_ACTIVE,
	LOCAL_ATTR_TYPE,
	LOCAL_ATTR_PRESET,
	LOCAL_ATTR_VALUE,
)
from core.constants.settings import *
from interlock_backend.settings import DEFAULT_SUPERUSER_USERNAME

### Rest Framework
from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework import status

### Views / Mixins
from core.views.ldap_settings import SettingsViewSet, SettingsViewMixin
from core.views.mixins.ldap.user import LDAPUserBaseMixin

### Other
from tests.test_core.test_views.conftest import (
	UserFactory,
	BaseViewTestClass,
	BaseViewTestClassWithPk,
)
from tests.test_core.conftest import ConnectorFactory
from typing import Protocol


@pytest.fixture(autouse=True)
def reset_settings_and_presets():
	LDAPPreset.objects.all().delete()
	LDAPSetting.objects.all().delete()


class LdapPresetFactory(Protocol):
	def __call__(
		self,
		name="test_preset",
		label="Test Preset",
		active=False,
	) -> LDAPPreset: ...


@pytest.fixture(autouse=True)
def f_resync_patch(mocker: MockerFixture):
	mocker.patch.object(SettingsViewSet, "resync_settings")


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
	if not User.objects.filter(username=DEFAULT_SUPERUSER_USERNAME).exists():
		return user_factory(username=DEFAULT_SUPERUSER_USERNAME, email=None)


@pytest.fixture
def f_log_mixin(mocker: MockerFixture):
	return mocker.patch("core.views.ldap_settings.DBLogMixin")


class TestList(BaseViewTestClass):
	_endpoint = "settings"

	def test_success(
		self,
		mocker: MockerFixture,
		fc_ldap_preset: LdapPresetFactory,
		admin_user_client: APIClient,
		admin_user: User,
		f_log_mixin,
	):
		f_preset_01 = fc_ldap_preset(
			name="test_preset_01", label="Test Preset 01", active=True
		)
		f_preset_02 = fc_ldap_preset(
			name="test_preset_02", label="Test Preset 02"
		)

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


class TestFetch(BaseViewTestClassWithPk):
	_endpoint = "settings-detail"

	@pytest.mark.parametrize(
		"superadmin_enabled",
		(
			True,
			False,
		),
		ids=[
			"With local superadmin",
			"Without local superadmin",
		],
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
			f_default_superadmin.deleted = not f_default_superadmin.deleted
			f_default_superadmin.save()
			f_default_superadmin.refresh_from_db()

		f_preset_01 = fc_ldap_preset(
			name="test_preset_01", label="Test Preset 01", active=True
		)
		self._pk = f_preset_01.id
		# Create entry for a second preset
		fc_ldap_preset(name="test_preset_02", label="Test Preset 02")

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
		assert (
			response_data["settings"]["local"]["DEFAULT_ADMIN_ENABLED"][
				LOCAL_ATTR_VALUE
			]
			== superadmin_enabled
		)
		assert isinstance(response_data["settings"]["local"], dict)
		assert isinstance(response_data["settings"]["ldap"], dict)


class TestPresetCreate(BaseViewTestClass):
	_endpoint = "settings"

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
			data={LOCAL_ATTR_LABEL: label},
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
			{"a": "dict"},
			["a", "list"],
		),
	)
	def test_raises_serializer_exc(
		self,
		admin_user_client: APIClient,
		label: str,
	):
		response: Response = admin_user_client.post(
			self.endpoint,
			data={LOCAL_ATTR_LABEL: label},
			format="json",
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert LDAPPreset.objects.count() == 0


class TestPresetDelete(BaseViewTestClassWithPk):
	_endpoint = "settings-detail"

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
		self._pk = m_preset.id

		response: Response = admin_user_client.delete(self.endpoint)

		assert response.status_code == status.HTTP_200_OK
		assert LDAPPreset.objects.filter(name=m_preset_name).count() == 0

	def test_raises_must_be_disabled(
		self,
		admin_user_client: APIClient,
		fc_ldap_preset: LdapPresetFactory,
	):
		m_preset_name = "test_preset_delete"
		m_preset = fc_ldap_preset(
			name=m_preset_name,
			label="Test Preset Delete",
			active=True,
		)
		m_preset.save()
		self._pk = m_preset.id

		response: Response = admin_user_client.delete(
			self.endpoint,
			data={LOCAL_ATTR_ID: m_preset.id},
			format="json",
		)

		assert response.status_code == status.HTTP_400_BAD_REQUEST
		m_preset.refresh_from_db()

	def test_preset_not_exists(
		self,
		admin_user_client: APIClient,
	):
		self._pk = 999
		response: Response = admin_user_client.delete(self.endpoint)

		assert response.status_code == status.HTTP_404_NOT_FOUND
		assert response.data.get("code") == "setting_preset_not_exists"


class TestPresetEnable(BaseViewTestClassWithPk):
	_endpoint = "settings-enable"

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
		self._pk = m_preset.id

		response: Response = admin_user_client.post(self.endpoint)

		assert response.status_code == status.HTTP_200_OK
		m_preset.refresh_from_db()
		assert m_preset.active
		assert LDAPPreset.objects.filter(active=True).count() == 1
		assert LDAPPreset.objects.get(active=True) == m_preset

	def test_raises_does_not_exist(
		self,
		admin_user_client: APIClient,
	):
		self._pk = 999
		response: Response = admin_user_client.post(
			self.endpoint,
			format="json",
		)

		assert response.status_code == status.HTTP_404_NOT_FOUND
		assert not LDAPPreset.objects.all().exists()
		assert response.data.get("code") == "setting_preset_not_exists"


class TestPresetRename(BaseViewTestClassWithPk):
	_endpoint = "settings-rename"

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
		self._pk = m_preset.id

		response: Response = admin_user_client.post(
			self.endpoint,
			data={LOCAL_ATTR_LABEL: "New Name"},
		)
		assert response.status_code == status.HTTP_200_OK

		m_preset.refresh_from_db()
		assert m_preset.name == "new_name"
		assert m_preset.label == "New Name"

	def test_raises_does_not_exist(
		self,
		admin_user_client: APIClient,
	):
		self._pk = 999

		response: Response = admin_user_client.post(
			self.endpoint,
			data={LOCAL_ATTR_LABEL: "New Name"},
			format="json",
		)

		assert response.status_code == status.HTTP_404_NOT_FOUND
		assert not LDAPPreset.objects.all().exists()
		assert response.data.get("code") == "setting_preset_not_exists"

	def test_raises_missing_key(
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
		self._pk = m_preset.id

		response: Response = admin_user_client.post(
			self.endpoint,
			data={},
			format="json",
		)

		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("code") == "data_key_missing"


class TestSave(BaseViewTestClass):
	_endpoint = "settings-save"

	def test_success(
		self,
		admin_user_client: APIClient,
		mocker: MockerFixture,
		fc_ldap_preset: LdapPresetFactory,
	):
		m_ldap_preset = fc_ldap_preset()
		m_set_admin_status = mocker.patch.object(
			SettingsViewSet,
			"set_admin_status",
		)
		m_save_local_settings = mocker.patch.object(
			SettingsViewSet,
			"save_local_settings",
		)
		m_save_ldap_settings = mocker.patch.object(
			SettingsViewSet,
			"save_ldap_settings",
		)
		m_resync_settings = mocker.patch.object(
			SettingsViewSet,
			"resync_settings",
		)
		m_admin_enabled = True
		m_admin_password = "mock_password"
		m_local_dict = {
			"DEFAULT_ADMIN_ENABLED": {
				LOCAL_ATTR_TYPE: TYPE_BOOL,
				LOCAL_ATTR_VALUE: m_admin_enabled,
			},
			"DEFAULT_ADMIN_PWD": {
				LOCAL_ATTR_TYPE: TYPE_STRING,
				LOCAL_ATTR_VALUE: m_admin_password,
			},
		}
		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				"preset": {"id": m_ldap_preset.id},
				"settings": {
					"local": m_local_dict,
					"ldap": "mock_ldap_dict",
				},
			},
			format="json",
		)
		assert response.status_code == status.HTTP_200_OK
		m_set_admin_status.assert_called_once_with(
			status=m_admin_enabled,
			password=m_admin_password,
		)
		m_save_local_settings.assert_called_once_with({})
		m_save_ldap_settings.assert_called_once_with(
			"mock_ldap_dict",
			m_ldap_preset,
		)
		m_resync_settings.assert_called_once()

	def test_raises_no_preset(self, admin_user_client: APIClient):
		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				"preset": {},
				"settings": {},
			},
			format="json",
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("code") == "data_key_missing"
		assert response.data.get("key") == "data.preset.id"

	def test_raises_preset_not_exists(self, admin_user_client: APIClient):
		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				"preset": {"id": 999},
				"settings": {
					"local": {},
					"ldap": {},
				},
			},
			format="json",
		)
		assert response.status_code == status.HTTP_404_NOT_FOUND
		assert response.data.get("code") == "setting_preset_not_exists"

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
				"settings": {
					"local": {
						"DEFAULT_ADMIN_ENABLED": {
							LOCAL_ATTR_TYPE: TYPE_BOOL,
							LOCAL_ATTR_VALUE: m_status,
						},
						"DEFAULT_ADMIN_PWD": {
							LOCAL_ATTR_TYPE: TYPE_STRING,
							LOCAL_ATTR_VALUE: m_password,
						},
					},
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


class TestReset(BaseViewTestClass):
	_endpoint = "settings-reset"

	def test_success(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		fc_ldap_preset: LdapPresetFactory,
	):
		m_ldap_preset = fc_ldap_preset(active=True)
		m_setting = LDAPSetting(
			**{
				LOCAL_ATTR_NAME: K_LDAP_AUTH_URL,
				LOCAL_ATTR_TYPE: TYPE_LDAP_URI,
				LOCAL_ATTR_PRESET: m_ldap_preset,
				LOCAL_ATTR_VALUE: ["ldap://127.1.1.1:389"],
			}
		)
		m_setting.save()
		assert LDAPPreset.objects.filter(active=True).count() == 1
		assert LDAPSetting.objects.filter(preset=m_ldap_preset.id).exists()

		m_resync_settings = mocker.patch.object(
			SettingsViewSet, "resync_settings"
		)
		response: Response = admin_user_client.get(self.endpoint)
		assert response.status_code == status.HTTP_200_OK

		m_resync_settings.assert_called_once()
		assert not LDAPSetting.objects.filter(preset=m_ldap_preset.id).exists()


class TestLdapTestEndpoint(BaseViewTestClass):
	_endpoint = "settings-test"

	def test_raises_setting_key_raises_bad_request(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		fc_ldap_preset: LdapPresetFactory,
	):
		m_ldap_preset = fc_ldap_preset(active=True)
		m_test_fn = mocker.patch.object(
			SettingsViewSet,
			"test_ldap_settings",
			return_value="mock_result",
		)
		m_data = SettingsViewMixin().get_ldap_settings(
			preset_id=m_ldap_preset.id
		)
		m_data["some_bad_key"] = True

		response: Response = admin_user_client.post(
			self.endpoint, data=m_data, format="json"
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert "Invalid field" in response.data.get("detail")
		m_test_fn.assert_not_called()

	def test_raises_setting_type_mismatch(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		fc_ldap_preset: LdapPresetFactory,
	):
		m_ldap_preset = fc_ldap_preset(active=True)
		m_test_fn = mocker.patch.object(
			SettingsViewSet,
			"test_ldap_settings",
			return_value="mock_result",
		)
		m_data = SettingsViewMixin().get_ldap_settings(
			preset_id=m_ldap_preset.id
		)
		m_data[K_LDAP_AUTH_USE_SSL][LOCAL_ATTR_TYPE] = TYPE_LDAP_URI

		response: Response = admin_user_client.post(
			self.endpoint, data=m_data, format="json"
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert "Invalid field type for" in response.data.get("detail")
		m_test_fn.assert_not_called()

	def test_raises_setting_value_invalid_choice(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		fc_ldap_preset: LdapPresetFactory,
	):
		m_ldap_preset = fc_ldap_preset(active=True)
		m_test_fn = mocker.patch.object(
			SettingsViewSet,
			"test_ldap_settings",
			return_value="mock_result",
		)
		m_data = SettingsViewMixin().get_ldap_settings(
			preset_id=m_ldap_preset.id
		)
		m_data[K_LDAP_AUTH_TLS_VERSION][LOCAL_ATTR_VALUE] = "some_bad_value"

		response: Response = admin_user_client.post(
			self.endpoint, data=m_data, format="json"
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert "field value is invalid" in response.data.get("detail")
		m_test_fn.assert_not_called()

	def test_raises_test_failed(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		fc_ldap_preset: LdapPresetFactory,
	):
		m_ldap_preset = fc_ldap_preset(active=True)
		m_test_fn = mocker.patch.object(
			SettingsViewSet,
			"test_ldap_settings",
			return_value=None,
		)
		m_data = SettingsViewMixin().get_ldap_settings(
			preset_id=m_ldap_preset.id
		)

		response: Response = admin_user_client.post(
			self.endpoint, data=m_data, format="json"
		)
		assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
		assert response.data.get("code") == "ldap_bind_test_failed"
		m_test_fn.assert_called_once_with(m_data)

	def test_success(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		fc_ldap_preset: LdapPresetFactory,
	):
		m_ldap_preset = fc_ldap_preset(active=True)
		m_test_fn = mocker.patch.object(
			SettingsViewSet,
			"test_ldap_settings",
			return_value="mock_result",
		)
		m_data = SettingsViewMixin().get_ldap_settings(
			preset_id=m_ldap_preset.id
		)

		response: Response = admin_user_client.post(
			self.endpoint, data=m_data, format="json"
		)
		assert response.status_code == status.HTTP_200_OK
		assert response.data.get("data") == "mock_result"
		m_test_fn.assert_called_once_with(m_data)


class TestSyncUsers(BaseViewTestClass):
	_endpoint = "settings-sync-users"

	def test_success(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		admin_user: User,
	):
		m_synced_users = ["mock_synced_users"]
		m_updated_users = ["mock_updated_users"]
		m_ldap_users_sync = mocker.patch.object(
			LDAPUserBaseMixin,
			"ldap_users_sync",
			return_value=(
				m_synced_users,
				m_updated_users,
			),
		)
		response: Response = admin_user_client.get(self.endpoint)
		assert response.status_code == status.HTTP_200_OK
		m_ldap_users_sync.assert_called_once_with(responsible_user=admin_user)
		assert response.data.get("synced_users") == m_synced_users
		assert response.data.get("updated_users") == m_updated_users


class TestPruneUsers(BaseViewTestClass):
	_endpoint = "settings-prune-users"

	def test_success(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		admin_user: User,
	):
		m_pruned_count = 3
		m_prune_fn = mocker.patch.object(
			LDAPUserBaseMixin, "ldap_users_prune", return_value=m_pruned_count
		)
		response: Response = admin_user_client.get(self.endpoint)
		assert response.status_code == status.HTTP_200_OK
		m_prune_fn.assert_called_once_with(responsible_user=admin_user)
		assert response.data.get("count") == m_pruned_count


class TestPurgeUsers(BaseViewTestClass):
	_endpoint = "settings-purge-users"

	def test_success(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		admin_user: User,
	):
		m_logger = mocker.patch("core.views.ldap_settings.logger")
		m_purged_count = 3
		m_purge_fn = mocker.patch.object(
			LDAPUserBaseMixin, "ldap_users_purge", return_value=m_purged_count
		)
		response: Response = admin_user_client.get(self.endpoint)
		assert response.status_code == status.HTTP_200_OK
		m_logger.warning.assert_called_once()
		m_purge_fn.assert_called_once_with(responsible_user=admin_user)
		assert response.data.get("count") == m_purged_count
