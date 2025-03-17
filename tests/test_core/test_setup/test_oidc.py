import pytest
from oidc_provider.models import RSAKey
from core.setup.oidc import create_default_oidc_rsa_key


@pytest.mark.django_db
def test_create_default_oidc_rsa_key_creates_new(mocker):
	key_value = "abc"

	m_export_key = mocker.MagicMock()
	m_export_key.decode.return_value = key_value

	m_key = mocker.MagicMock()
	m_key.exportKey.return_value = m_export_key

	m_patch = mocker.patch("Cryptodome.PublicKey.RSA.generate", return_value=m_key)
	assert RSAKey.objects.count() == 0
	create_default_oidc_rsa_key()
	assert RSAKey.objects.count() == 1
	assert RSAKey.objects.first().key == key_value
	m_patch.assert_called()
	m_key.exportKey.assert_called()
