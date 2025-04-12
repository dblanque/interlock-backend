import pytest
from core.models.ldap_settings import LDAPSetting, LDAPPreset, LDAP_SETTING_MAP
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton, get_settings
from core.ldap import defaults as ldap_defaults
from pytest_mock import MockType
from interlock_backend.encrypt import aes_encrypt
from inspect import getmembers, isroutine


# Teardown singleton for each test.
@pytest.fixture(autouse=True)
def reset_singleton():
	yield
	RuntimeSettingsSingleton._instance = None


@pytest.fixture
def f_runtime_settings():
	"""Provides a clean instance of the RuntimeSettingsSingleton"""
	instance = RuntimeSettingsSingleton()
	yield instance


@pytest.fixture
def f_ldap_settings(mocker):
	"""Mocks the LDAPSetting model"""
	return mocker.patch("core.models.ldap_settings.LDAPSetting")


@pytest.fixture
def f_ldap_preset(mocker):
	"""Mocks the LDAPPreset model"""
	return mocker.patch("core.models.ldap_settings.LDAPPreset")


@pytest.fixture
def f_db_exists(mocker):
	"""Mocks db_table_exists"""
	return mocker.patch("core.models.ldap_settings_runtime.db_table_exists")


def test_singleton_creates_only_one_instance():
	"""Verify only one instance exists even with multiple instantiations"""
	instance1 = RuntimeSettingsSingleton()
	instance2 = RuntimeSettingsSingleton()
	instance3 = RuntimeSettingsSingleton()

	assert instance1 is instance2
	assert instance2 is instance3
	assert id(instance1) == id(instance2) == id(instance3)


def test_singleton_maintains_state_across_references():
	"""Verify state changes are visible across all references"""
	instance1 = RuntimeSettingsSingleton()
	instance2 = RuntimeSettingsSingleton()

	# Modify through instance1
	original_value = instance1.LDAP_AUTH_URL
	new_value = "ldap://new.example.com"
	instance1.LDAP_AUTH_URL = new_value

	# Verify change visible through instance2
	assert instance2.LDAP_AUTH_URL == new_value
	assert instance1.LDAP_AUTH_URL == instance2.LDAP_AUTH_URL

	# Restore original value
	instance1.LDAP_AUTH_URL = original_value


def test_singleton_after_del_and_recreate():
	"""Verify singleton persists even after del and recreate"""
	instance1 = RuntimeSettingsSingleton()
	original_id = id(instance1)

	# Delete reference and create new one
	del instance1
	instance2 = RuntimeSettingsSingleton()

	assert id(instance2) == original_id


def test_singleton_with_multiple_threads():
	"""Verify thread-safe singleton behavior (basic check)"""
	from threading import Thread

	instances = []

	def get_instance():
		instances.append(RuntimeSettingsSingleton())

	threads = [Thread(target=get_instance) for _ in range(5)]
	[t.start() for t in threads]
	[t.join() for t in threads]

	# Verify all instances are the same
	assert all(instance is instances[0] for instance in instances)


def test_singleton_uuid_behavior():
	"""Verify UUID changes on resync but instance remains the same"""
	instance1 = RuntimeSettingsSingleton()
	original_uuid = instance1.uuid

	# First verify same instance
	instance2 = RuntimeSettingsSingleton()
	assert instance1 is instance2

	# Trigger resync which should generate new UUID
	instance1.resync()
	new_uuid = instance1.uuid

	# UUID should change
	assert original_uuid != new_uuid
	# But instance should remain the same
	assert instance1 is instance2
	assert instance2.uuid == new_uuid  # Change visible through other reference


def test_all_properties_initialized():
	instance = RuntimeSettingsSingleton()
	for prop in dir(ldap_defaults):
		if not prop.startswith("__") and not prop.endswith("__"):
			assert hasattr(instance, prop)


def test_init_calls_newuuid_and_resync(mocker):
	"""Test that __init__ calls __newUuid__ and resync()"""
	# Setup mocks
	mock_new_uuid = mocker.patch.object(RuntimeSettingsSingleton, "__newUuid__", autospec=True)
	mock_resync = mocker.patch.object(
		RuntimeSettingsSingleton, "resync", autospec=True, return_value=True
	)

	# Instantiate
	instance = RuntimeSettingsSingleton()

	# Verify mocks were called
	mock_new_uuid.assert_called_once_with(instance)
	mock_resync.assert_called_once_with(instance)


def test_init_sets_default_values(mocker):
	"""Test that __init__ sets all default values"""
	# Setup mocks
	mocker.patch.object(RuntimeSettingsSingleton, "__newUuid__")
	mocker.patch.object(RuntimeSettingsSingleton, "resync", return_value=True)

	# Instantiate
	instance = RuntimeSettingsSingleton()

	# Verify default values are set
	for attr in dir(ldap_defaults):
		if not attr.startswith("_"):
			assert hasattr(instance, attr)
			assert getattr(instance, attr) == getattr(ldap_defaults, attr)


def test_init_handles_resync_failure(mocker):
	"""Test that __init__ continues even if resync fails"""
	# Setup mocks
	mocker.patch.object(RuntimeSettingsSingleton, "__newUuid__")
	mocker.patch.object(RuntimeSettingsSingleton, "resync", return_value=False)

	# Instantiate - should not raise exception
	instance = RuntimeSettingsSingleton()

	# Verify defaults are still set
	assert hasattr(instance, "LDAP_AUTH_URL")
	assert instance.LDAP_AUTH_URL == ldap_defaults.LDAP_AUTH_URL


def test_init_sets_uuid(mocker):
	"""Test that __init__ properly sets UUID"""
	# Setup mock return value
	test_uuid = "test-uuid-1234"
	mock_new_uuid = mocker.patch.object(
		RuntimeSettingsSingleton,
		"__newUuid__",
		side_effect=lambda self: setattr(self, "uuid", test_uuid),
		autospec=True,
	)
	mocker.patch.object(RuntimeSettingsSingleton, "resync", return_value=True)

	# Instantiate
	instance = RuntimeSettingsSingleton()

	# Verify UUID was set
	assert instance.uuid == test_uuid
	mock_new_uuid.assert_called_once()


def test_init_with_existing_instance(mocker):
	"""Test that __init__ works properly when instance already exists"""
	# Create initial instance
	original_instance = RuntimeSettingsSingleton()
	original_uuid = original_instance.uuid

	# Setup mocks - these shouldn't be called on subsequent inits
	mock_new_uuid = mocker.patch.object(
		RuntimeSettingsSingleton, "__newUuid__", wraps=original_instance.__newUuid__
	)
	mock_resync = mocker.patch.object(
		RuntimeSettingsSingleton, "resync", wraps=original_instance.resync
	)

	# Create new instance
	new_instance = RuntimeSettingsSingleton()

	# Verify same instance and no new calls to mocked methods
	assert new_instance is original_instance
	mock_new_uuid.assert_not_called()
	mock_resync.assert_not_called()
	assert new_instance.uuid == original_uuid


def test_postsync():
	instance = RuntimeSettingsSingleton()
	FIELDS_TO_CHECK = [
		instance.LDAP_AUTH_USER_FIELDS["username"],
		"username",
	]
	for f in FIELDS_TO_CHECK:
		if f in instance.LDAP_DIRTREE_ATTRIBUTES:
			instance.LDAP_DIRTREE_ATTRIBUTES.remove(f)
	instance.postsync()
	for f in FIELDS_TO_CHECK:
		assert f in instance.LDAP_DIRTREE_ATTRIBUTES


def test_resync_with_defaults(mocker):
	m_logger = mocker.patch("core.models.ldap_settings_runtime.logger")
	mocker.patch.object(RuntimeSettingsSingleton, "__init__", return_value=None)
	instance = RuntimeSettingsSingleton()
	instance.__newUuid__()

	m_new_uuid: MockType = mocker.patch.object(
		RuntimeSettingsSingleton, RuntimeSettingsSingleton.__newUuid__.__name__
	)
	m_get_settings: MockType = mocker.patch(
		f"core.models.ldap_settings_runtime.{get_settings.__name__}"
	)
	m_postsync: MockType = mocker.patch.object(
		RuntimeSettingsSingleton, RuntimeSettingsSingleton.postsync.__name__
	)
	instance.resync()
	m_new_uuid.assert_called_once()
	m_get_settings.assert_called_once_with(instance.uuid)
	m_postsync.assert_called_once()

	ldap_default_settings = getmembers(RuntimeSettingsSingleton, lambda a: not (isroutine(a)))
	for setting_key, default_value in ldap_default_settings:
		if setting_key.startswith("__") and setting_key.endswith("__"):
			continue
		assert default_value == getattr(instance, setting_key)


def test_resync_raises_exception(mocker):
	mocker.patch.object(RuntimeSettingsSingleton, "__init__", return_value=None)
	instance = RuntimeSettingsSingleton()

	m_new_uuid: MockType = mocker.patch.object(
		RuntimeSettingsSingleton, RuntimeSettingsSingleton.__newUuid__.__name__
	)
	m_get_settings: MockType = mocker.patch(
		f"core.models.ldap_settings_runtime.{get_settings.__name__}", side_effect=Exception
	)
	m_postsync: MockType = mocker.patch.object(
		RuntimeSettingsSingleton, RuntimeSettingsSingleton.postsync.__name__
	)
	with pytest.raises(Exception):
		instance.resync(raise_exc=True)
	m_new_uuid.assert_called_once()
	m_get_settings.assert_not_called()
	m_postsync.assert_not_called()


def test_resync_returns_false_on_exception(mocker):
	mocker.patch.object(RuntimeSettingsSingleton, "__init__", return_value=None)
	instance = RuntimeSettingsSingleton()

	mocker.patch.object(RuntimeSettingsSingleton, RuntimeSettingsSingleton.__newUuid__.__name__)
	mocker.patch(
		f"core.models.ldap_settings_runtime.{get_settings.__name__}", side_effect=Exception
	)
	m_postsync: MockType = mocker.patch.object(
		RuntimeSettingsSingleton, RuntimeSettingsSingleton.postsync.__name__
	)
	assert instance.resync() is False
	m_postsync.assert_not_called()


def test_get_settings_no_preset():
	m_settings = get_settings("non-existing-uuid")
	for s_key, s_val in m_settings.items():
		assert s_val == getattr(ldap_defaults, s_key)


def test_get_settings_tables_do_not_exist(mocker):
	mocker.patch("core.models.ldap_settings_runtime.db_table_exists", return_value=False)
	m_logger = mocker.patch("core.models.ldap_settings_runtime.logger")
	m_settings = get_settings("non-existing-uuid")
	for s_key, s_val in m_settings.items():
		assert s_val == getattr(ldap_defaults, s_key)
	m_logger.warning.call_count == 2


@pytest.mark.django_db
class TestLDAPSettingsWithDB:
	@pytest.fixture(autouse=True)
	def reset_settings_and_presets(self):
		LDAPPreset.objects.all().delete()
		LDAPSetting.objects.all().delete()

	@pytest.fixture
	def f_ldap_settings_preset(self):
		return LDAPPreset.objects.create(
			name="mock_preset",
			label="Mock Preset",
			active=True,
		)

	@pytest.mark.parametrize(
		"test_key, test_value, expected_result",
		(
			(  # TYPE_LDAP_URI
				"LDAP_AUTH_URL",
				["ldap://127.0.0.2:389"],
				None,
			),
			(  # TYPE_STRING
				"LDAP_DOMAIN",
				"sub.example.com",
				None,
			),
			(  # TYPE_AES_ENCRYPT
				"LDAP_AUTH_CONNECTION_PASSWORD",
				(b"m_encrypted_aes_key", b"m_ciphertext", b"m_nonce", b"m_tag"),
				"mockPassword1234",
			),
			(  # TYPE_BOOL
				"LDAP_AUTH_USE_TLS",
				True,
				None,
			),
			(  # TYPE_LDAP_TLS_VERSION
				"LDAP_AUTH_TLS_VERSION",
				"PROTOCOL_TLSv1",
				None,
			),
			(  # TYPE_INTEGER
				"LDAP_LOG_MAX",
				99,
				None,
			),
		),
	)
	def test_get_settings_mock_db_overrides(
		self, test_key, test_value, expected_result, mocker, f_ldap_settings_preset
	):
		if not expected_result:
			expected_result = test_value
		if test_key == "LDAP_AUTH_CONNECTION_PASSWORD":
			m_aes_decrypt: MockType = mocker.patch(
				"core.models.ldap_settings_runtime.aes_decrypt", return_value=expected_result
			)
		LDAPSetting.objects.create(
			name=test_key,
			type=LDAP_SETTING_MAP.get(test_key),
			value=test_value,
			preset=f_ldap_settings_preset,
		)

		m_settings = get_settings("non-existing-uuid", quiet=True)
		assert m_settings.get(test_key) == expected_result
		if test_key == "LDAP_AUTH_CONNECTION_PASSWORD":
			m_aes_decrypt.assert_called_once()

	def test_get_settings_decrypt(self, f_ldap_settings_preset):
		m_key = "LDAP_AUTH_CONNECTION_PASSWORD"
		m_value = "mockPassword1234"
		LDAPSetting.objects.create(
			name=m_key,
			type=LDAP_SETTING_MAP.get(m_key),
			value=aes_encrypt(m_value),
			preset=f_ldap_settings_preset,
		)

		m_settings = get_settings("non-existing-uuid", quiet=True)
		assert m_settings.get(m_key) == m_value
