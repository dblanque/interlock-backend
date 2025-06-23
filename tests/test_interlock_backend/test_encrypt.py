import pytest
from Cryptodome.PublicKey import RSA
from pytest_mock import MockType
from core.models.interlock_settings import (
	InterlockSetting,
	INTERLOCK_SETTING_AES_KEY,
	INTERLOCK_SETTING_MAP,
)
from interlock_backend.test_settings import SECRET_KEY
from interlock_backend.encrypt import (
	RSA_KEY_BITS,
	create_rsa_key,
	import_rsa_key,
	import_or_create_rsa_key,
	fernet_encrypt,
	fernet_decrypt,
)


@pytest.mark.django_db
def test_create_rsa_key(mocker):
	# Mock the RSA.generate method to return a mock RSA key
	m_key = mocker.MagicMock(spec=RSA.RsaKey)
	m_key.export_key.return_value = b"mocked_exported_key"

	# Mock InterlockSetting.objects.create
	m_db_obj = mocker.MagicMock()
	# Mock save method
	m_db_obj.save = mocker.MagicMock()

	m_generate: MockType = mocker.patch(
		"interlock_backend.encrypt.RSA.generate", return_value=m_key
	)
	m_create: MockType = mocker.patch(
		"core.models.interlock_settings.InterlockSetting.objects.create",
		return_value=m_db_obj,
	)
	result = create_rsa_key()

	# Assertions
	# Verify that RSA.generate was called with the correct arguments
	m_generate.assert_called_once_with(RSA_KEY_BITS)

	# Verify that InterlockSetting.objects.create was called with the correct arguments
	m_create.assert_called_once_with(
		name=INTERLOCK_SETTING_AES_KEY,
		type=INTERLOCK_SETTING_MAP[INTERLOCK_SETTING_AES_KEY],
		value=m_key.export_key.return_value,
	)

	# Verify that the mock_db_obj.save method was called
	m_db_obj.save.assert_called_once()

	# Verify that the function returned the correct RSA key
	assert result == m_key


@pytest.mark.django_db
def test_import_rsa_key_when_exists(mocker):
	"""
	Test the `import_rsa_key` function when the key exists in the database.
	"""
	# Mock InterlockSetting
	m_db_obj: MockType = mocker.MagicMock()
	m_db_obj.value = b"mocked_key_value"

	# Mock the RSA.generate method to return a mock RSA key
	m_key = mocker.MagicMock(spec=RSA.RsaKey)

	# Mocked internal functions
	m_get: MockType = mocker.patch(
		"core.models.interlock_settings.InterlockSetting.objects.get",
		return_value=m_db_obj,
	)
	m_import_key: MockType = mocker.patch(
		"interlock_backend.encrypt.RSA.import_key", return_value=m_key
	)
	result = import_rsa_key()

	m_get.assert_called_once_with(
		name=INTERLOCK_SETTING_AES_KEY,
		type=INTERLOCK_SETTING_MAP[INTERLOCK_SETTING_AES_KEY],
	)
	m_import_key.assert_called_once_with(m_db_obj.value, passphrase=SECRET_KEY)
	assert result == m_key


def test_import_or_create_rsa_key_when_not_exists(mocker):
	mocker.patch(
		"core.models.interlock_settings.InterlockSetting.objects.get",
		return_value=None,
		side_effect=InterlockSetting.DoesNotExist,
	)
	result = import_rsa_key()
	assert result is None


def test_import_or_create_rsa_key_when_imported(mocker):
	# Mock the RSA.generate method to return a mock RSA key
	m_key = mocker.MagicMock(spec=RSA.RsaKey)
	m_import_rsa_key: MockType = mocker.patch(
		"interlock_backend.encrypt.import_rsa_key",
		return_value=m_key,
	)
	m_create_rsa_key: MockType = mocker.patch(
		"interlock_backend.encrypt.create_rsa_key",
		return_value=None,
	)
	result = import_or_create_rsa_key()
	m_import_rsa_key.assert_called_once()
	m_create_rsa_key.assert_not_called()
	assert result == m_key


def test_import_or_create_rsa_key_when_created(mocker):
	# Mock the RSA.generate method to return a mock RSA key
	m_key = mocker.MagicMock(spec=RSA.RsaKey)
	m_import_rsa_key: MockType = mocker.patch(
		"interlock_backend.encrypt.import_rsa_key",
		return_value=None,
	)
	m_create_rsa_key: MockType = mocker.patch(
		"interlock_backend.encrypt.create_rsa_key",
		return_value=m_key,
	)
	result = import_or_create_rsa_key()
	m_import_rsa_key.assert_called_once()
	m_create_rsa_key.assert_called_once()
	assert result == m_key


@pytest.mark.parametrize(
	"data,return_bytes,bytes_encoding,expected",
	(
		("test1234", False, "utf-8", "abcd1234"),
		("test1234", True, "utf-8", b"abcd1234"),
	),
)
def test_fernet_encrypt(data, return_bytes, bytes_encoding, expected, mocker):
	# We don't need to test the fernet encryption, its a library.
	m_fernet = mocker.Mock()
	mocker.patch("interlock_backend.encrypt.Fernet", return_value=m_fernet)
	m_fernet.encrypt.return_value = b"abcd1234"
	assert fernet_encrypt(data, return_bytes, bytes_encoding) == expected


@pytest.mark.parametrize(
	"data,bytes_encoding,expected",
	(("abcd4321", "utf-8", "abcd4321"), (b"abcd1234", "utf-8", "abcd1234")),
)
def test_fernet_decrypt(data, bytes_encoding, expected, mocker):
	# We don't need to test the fernet decryption, its a library.
	m_fernet = mocker.Mock()
	mocker.patch("interlock_backend.encrypt.Fernet", return_value=m_fernet)
	m_fernet.decrypt.return_value = bytes(expected, bytes_encoding)
	assert fernet_decrypt(data, bytes_encoding) == expected
