from django.core.management.base import BaseCommand, CommandError
from interlock_backend.encrypt import fernet_encrypt
from django.utils.crypto import get_random_string

class Command(BaseCommand):
	help = "Generates Linux PAM API Client Key Pair"

	def handle(self, *args, **options):
		try:
			KEY = get_random_string(24, "abcdefghijklmnopqrstuvwxyz0123456789")
			ENCRYPTED_KEY = fernet_encrypt(KEY)
			self.stdout.write(
				"Add the following to your Linux PAM Authentication Config File"
				" (default path: /usr/share/pam-python/pam_rest_auth_conf.py):"
			)
			self.stdout.write(
				self.style.SUCCESS("\tRECV_EXPECTED = %s" % (KEY))
			)
			self.stdout.write(
				self.style.SUCCESS("\tSEND_ENCRYPTED = %s" % (ENCRYPTED_KEY))
			)
		except:
			raise CommandError(
				"Could not generate Linux PAM API Client Key-pair."
			)
