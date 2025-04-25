import pytest
from pytest_mock import MockType
from django.db import transaction
from core.models.interlock_settings import (
	InterlockSetting,
	INTERLOCK_SETTING_ENABLE_LDAP,
)
from core.models.types.settings import TYPE_BOOL
from core.models.user import User, USER_TYPE_LDAP
from core.models.ldap_settings import LDAPPreset
from core.exceptions import ldap as exc_ldap
from core.views.mixins.ldap_settings import SettingsViewMixin


@pytest.fixture(autouse=True)
def auto_teardown():
	yield
	LDAPPreset.objects.all().delete()


@pytest.fixture(autouse=True)
def f_runtime_settings(mocker, g_runtime_settings):
	mocker.patch("core.views.mixins.ldap_settings.RuntimeSettings")
	return g_runtime_settings


@pytest.fixture
def mixin():
	"""Fixture providing an instance of the mixin class"""
	return SettingsViewMixin()


@pytest.fixture
def test_user():
	"""Fixture creating a test user in the database"""
	return User.objects.create_user(
		username="testuser",
		password="testpass",
		email="test@example.com",
		user_type=USER_TYPE_LDAP,
	)


@pytest.fixture
def test_admin_user():
	"""Fixture creating an admin user in the database"""
	return User.objects.create_superuser(
		username="admin", password="adminpass", email="admin@example.com"
	)


@pytest.fixture
def ldap_setting():
	"""Fixture creating LDAP setting in the database"""
	return InterlockSetting.objects.create(
		name=INTERLOCK_SETTING_ENABLE_LDAP, value=True, type=TYPE_BOOL
	)


@pytest.fixture
def ldap_preset():
	"""Fixture creating LDAP preset in the database"""
	return LDAPPreset.objects.create(
		name="test_preset", label="Test Preset", active=True
	)


@pytest.fixture
def ldap_test_data() -> dict:
	"""Fixture providing sample LDAP test data"""
	return {
		"LDAP_AUTH_CONNECTION_USER_DN": {"value": "cn=admin,dc=example,dc=com"},
		"LDAP_AUTH_CONNECTION_PASSWORD": {"value": "password"},
		"LDAP_AUTH_URL": {"value": ["ldap://localhost:389"]},
		"LDAP_AUTH_CONNECT_TIMEOUT": {"value": "10"},
		"LDAP_AUTH_RECEIVE_TIMEOUT": {"value": "10"},
		"LDAP_AUTH_USE_SSL": {"value": False},
		"LDAP_AUTH_USE_TLS": {"value": True},
		"LDAP_AUTH_TLS_VERSION": {"value": "1.2"},
	}


################################################################################
# Tests
################################################################################


@pytest.mark.django_db
class TestLDAPSettingsMixin:
	def test_create_default_preset(self, mixin: SettingsViewMixin):
		assert LDAPPreset.objects.count() == 0
		mixin.create_default_preset()
		assert LDAPPreset.objects.count() == 1
		preset = LDAPPreset.objects.first()
		assert preset.name == "default_preset"
		assert preset.label == "Default Preset"
		assert preset.active is True

	def test_remove_default_preset(self, mixin: SettingsViewMixin):
		mixin.create_default_preset()
		assert LDAPPreset.objects.count() == 1
		mixin.remove_default_preset()
		assert LDAPPreset.objects.count() == 0

	def test_resync_users_ldap_disabled(self, mocker, mixin: SettingsViewMixin):
		# Setup
		mixin.resync_users = SettingsViewMixin.resync_users

		# Create test data
		InterlockSetting.objects.create(
			name=INTERLOCK_SETTING_ENABLE_LDAP, value=False, type=TYPE_BOOL
		)
		User.objects.create(username="testuser", user_type=USER_TYPE_LDAP)

		# Mock LDAP connector to ensure it's not called when LDAP is disabled
		m_connector = mocker.patch(
			"core.views.mixins.ldap_settings.LDAPConnector"
		)

		# Execute
		result = mixin.resync_users(mixin)

		# Verify
		assert result is None
		m_connector.assert_not_called()

	def test_resync_users_ldap_enabled_success(
		self, mocker, mixin: SettingsViewMixin, ldap_setting, test_user: User
	):
		# Mock LDAP connector and operations
		m_connector = mocker.MagicMock()
		m_ldap_instance = mocker.MagicMock()
		m_ldap_instance.get_user.return_value = test_user

		mocker.patch(
			"core.views.mixins.ldap_settings.LDAPConnector",
			return_value=m_connector,
		)
		m_connector.__enter__.return_value = m_ldap_instance

		# Execute
		result = mixin.resync_users()

		# Verify
		assert result is None
		m_ldap_instance.get_user.assert_called_once_with(username="testuser")
		test_user.refresh_from_db()  # Verify user was saved

	def test_resync_users_ldap_enabled_with_error(
		self, mocker, mixin: SettingsViewMixin, ldap_setting, test_user
	):
		# Mock LDAP connector and operations
		m_connector = mocker.MagicMock()
		m_ldap_instance = mocker.MagicMock()
		m_ldap_instance.get_user.side_effect = Exception("Some LDAP error.")

		mocker.patch(
			"core.views.mixins.ldap_settings.LDAPConnector",
			return_value=m_connector,
		)
		m_connector.__enter__.return_value = m_ldap_instance

		# Mock logger
		m_logger = mocker.MagicMock()
		mocker.patch("core.views.mixins.ldap_settings.logger", m_logger)

		# Execute
		result = mixin.resync_users()

		# Verify
		assert result is None
		m_logger.warning.assert_called_once()
		m_logger.exception.assert_called_once()

	def test_resync_users_ldap_setting_missing(
		self, mocker, mixin: SettingsViewMixin
	):
		# Ensure setting doesn't exist
		InterlockSetting.objects.filter(
			name=INTERLOCK_SETTING_ENABLE_LDAP
		).delete()

		# Mock logger
		m_logger = mocker.MagicMock()
		mocker.patch("core.views.mixins.ldap_settings.logger", m_logger)

		# Mock LDAP connector to ensure it's not called
		m_connector = mocker.patch(
			"core.views.mixins.ldap_settings.LDAPConnector"
		)

		# Execute
		result = mixin.resync_users()

		# Verify
		assert result is None
		m_logger.warning.assert_called_with(
			f"Could not fetch {INTERLOCK_SETTING_ENABLE_LDAP} from Database."
		)
		m_connector.assert_not_called()

	def test_resync_users_multiple_users(
		self, mocker, mixin: SettingsViewMixin, ldap_setting
	):
		User.objects.create(username="user1", user_type=USER_TYPE_LDAP)
		User.objects.create(username="user2", user_type=USER_TYPE_LDAP)

		# Mock LDAP connector and operations
		m_connector = mocker.MagicMock()
		m_ldap_instance = mocker.MagicMock()
		m_ldap_instance.get_user.side_effect = (
			lambda username: User.objects.get(username=username)
		)

		mocker.patch(
			"core.views.mixins.ldap_settings.LDAPConnector",
			return_value=m_connector,
		)
		m_connector.__enter__.return_value = m_ldap_instance

		# Execute
		result = mixin.resync_users()

		# Verify
		assert result is None
		assert m_ldap_instance.get_user.call_count == 2
		calls = [mocker.call(username="user1"), mocker.call(username="user2")]
		m_ldap_instance.get_user.assert_has_calls(calls, any_order=True)

	@pytest.mark.parametrize(
		"test_value, expected",
		(
			("Test Preset", "test_preset"),
			("Another Test", "another_test"),
			("MixedCase 123", "mixedcase_123"),
		),
	)
	def test_normalize_preset_name(
		self, mixin: SettingsViewMixin, test_value, expected
	):
		assert mixin.normalize_preset_name(test_value) == expected

	def test_get_active_settings_preset_exists(
		self, mixin: SettingsViewMixin, ldap_preset
	):
		preset = mixin.get_active_settings_preset()
		assert preset.id == ldap_preset.id

	def test_get_active_settings_preset_not_exists(
		self, mixin: SettingsViewMixin
	):
		assert LDAPPreset.objects.count() == 0
		preset = mixin.get_active_settings_preset()
		assert preset.name == "default_preset"
		assert LDAPPreset.objects.count() == 1

	def test_resync_settings(self, mixin: SettingsViewMixin, mocker):
		m_resync: MockType = mocker.patch(
			"core.views.mixins.ldap_settings.RuntimeSettings.resync"
		)
		m_resync_users: MockType = mocker.patch.object(mixin, "resync_users")
		mixin.resync_settings()
		m_resync.assert_called_once()
		m_resync_users.assert_called_once()

	def test_get_admin_status_exists_active(
		self, mixin: SettingsViewMixin, test_admin_user: User
	):
		status = mixin.get_admin_status()
		assert status is True

	def test_get_admin_status_exists_inactive(
		self, mixin: SettingsViewMixin, test_admin_user: User
	):
		test_admin_user.deleted = True
		test_admin_user.save()
		status = mixin.get_admin_status()
		assert status is False

	def test_get_admin_status_not_exists(self, mixin: SettingsViewMixin):
		status = mixin.get_admin_status()
		assert status is False

	def test_set_admin_status_activate(self, mixin: SettingsViewMixin):
		assert User.objects.filter(username="admin").count() == 0
		with transaction.atomic():
			mixin.set_admin_status(True)
		admin = User.objects.get(username="admin")
		assert admin.deleted is False

	def test_set_admin_status_deactivate(
		self, mixin: SettingsViewMixin, test_admin_user: User
	):
		with transaction.atomic():
			mixin.set_admin_status(False)
		test_admin_user.refresh_from_db()
		assert test_admin_user.deleted is True

	def test_set_admin_status_with_password(
		self, mixin: SettingsViewMixin, test_admin_user: User
	):
		new_password = "newadminpass"
		with transaction.atomic():
			mixin.set_admin_status(True, new_password)
		test_admin_user.refresh_from_db()
		assert test_admin_user.check_password(new_password)

	def test_set_admin_status_invalid_type(self, mixin: SettingsViewMixin):
		with pytest.raises(TypeError):
			mixin.set_admin_status("not_a_bool")

	def test_test_ldap_settings_success(
		self, mixin: SettingsViewMixin, ldap_test_data: dict, mocker
	):
		mocker.patch(
			"core.views.mixins.ldap_settings.net_port_test", return_value=True
		)
		m_test_conn = mocker.patch(
			"core.views.mixins.ldap_settings.test_ldap_connection"
		)

		m_conn = mocker.MagicMock()
		m_conn.result = {"success": True}
		m_test_conn.return_value = m_conn

		result = mixin.test_ldap_settings(ldap_test_data)

		assert result["success"] is True
		m_test_conn.assert_called_once()

	def test_test_ldap_settings_port_unreachable(
		self, mixin: SettingsViewMixin, ldap_test_data: dict, mocker
	):
		mocker.patch(
			"core.views.mixins.ldap_settings.net_port_test", return_value=False
		)
		with pytest.raises(exc_ldap.PortUnreachable):
			mixin.test_ldap_settings(ldap_test_data)

	def test_test_ldap_settings_connection_failed(
		self, mixin: SettingsViewMixin, ldap_test_data: dict, mocker
	):
		mocker.patch(
			"core.views.mixins.ldap_settings.net_port_test", return_value=True
		)
		mocker.patch(
			"core.views.mixins.ldap_settings.test_ldap_connection",
			side_effect=Exception,
		)
		with pytest.raises(exc_ldap.CouldNotOpenConnection):
			mixin.test_ldap_settings(ldap_test_data)

	def test_test_ldap_settings_invalid_timeout(
		self, mixin: SettingsViewMixin, ldap_test_data: dict
	):
		invalid_data = ldap_test_data.copy()
		invalid_data["LDAP_AUTH_CONNECT_TIMEOUT"]["value"] = "invalid"

		with pytest.raises(ValueError):
			mixin.test_ldap_settings(invalid_data)
