# myapp/apps.py
from django.apps import AppConfig


class CoreConfig(AppConfig):
	name = "core"

	def ready(self):
		# DEFAULT SUPERUSER CREATION
		from core.setup.user import create_default_superuser

		create_default_superuser()

		# DEFAULT SETTINGS CREATION
		from core.setup.interlock_setting import create_default_interlock_settings

		create_default_interlock_settings()

		from core.setup.oidc import create_default_oidc_rsa_key

		create_default_oidc_rsa_key()

		print("Core startup complete.")
