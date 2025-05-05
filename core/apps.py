# myapp/apps.py
from django.apps import AppConfig


class CoreConfig(AppConfig):
	name = "core"

	def ready(self):
		# DEFAULT SUPERUSER CREATION
		from core.setup.user import create_default_superuser

		create_default_superuser()

		# DEFAULT INTERLOCK SETTINGS CREATION
		from core.setup.interlock_setting import (
			create_default_interlock_settings,
		)

		create_default_interlock_settings()

		# DEFAULT LDAP SETTINGS PRESET CREATION
		from core.views.mixins.ldap_settings import SettingsViewMixin

		SettingsViewMixin().create_default_preset()

		# OIDC Key Automatic Creation

		from core.setup.oidc import create_default_oidc_rsa_key

		create_default_oidc_rsa_key()

		from logging import getLogger

		logger = getLogger()
		logger.info("Core startup complete.")
