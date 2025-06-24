from core.utils.db import db_table_exists


def create_default_oidc_rsa_key():
	if not db_table_exists("oidc_provider_rsakey"):
		return
	from oidc_provider.models import RSAKey
	from Cryptodome.PublicKey.RSA import generate

	if RSAKey.objects.count() <= 0:
		key = generate(2048)
		rsakey = RSAKey(key=key.exportKey("PEM").decode("utf8"))
		rsakey.save()
