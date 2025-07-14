################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.apps
# Contains the Core App initialization class

# ---------------------------------- IMPORTS --------------------------------- #
from django.apps import AppConfig
from core.utils.apps_ready import ensure_apps_ready
from core.utils.migrations import is_in_migration
from logging import getLogger
import threading
################################################################################

logger = getLogger()


class CoreConfig(AppConfig):
	name = "core"

	def ready(self):
		"""Non-blocking initialization trigger"""
		threading.Thread(target=self._delayed_init).start()

	def _delayed_init(self):
		"""Background thread to wait for app readiness"""
		ensure_apps_ready()  # Blocks until ready

		logger.info("All applications ready.")
		self._run_initializers()

	def _run_initializers(self):
		"""Initialization function"""
		# Imports that require Database Initialization
		# ! Don't move outside of function scope
		from core.setup.user import create_default_superuser
		from core.setup.interlock_setting import (
			create_default_interlock_settings,
		)
		from core.views.mixins.ldap_settings import SettingsViewMixin
		from core.setup.oidc import create_default_oidc_rsa_key

		if not is_in_migration():
			logger.info("Checking defaults.")

		create_default_superuser()
		create_default_interlock_settings()
		SettingsViewMixin().create_default_preset()
		create_default_oidc_rsa_key()
		if not is_in_migration():
			logger.info("Core startup complete.")
