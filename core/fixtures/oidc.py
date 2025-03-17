
def create_default_oidc_rsa_key():
	from oidc_provider.models import RSAKey
	from Cryptodome.PublicKey import RSA

	if RSAKey.objects.count() <= 0:
		key = RSA.generate(2048)
		rsakey = RSAKey(key=key.exportKey("PEM").decode("utf8"))
		rsakey.save()
