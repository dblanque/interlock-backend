# core/apps.py
from django.apps import AppConfig
from core.utils.apps_ready import ensure_apps_ready
from logging import getLogger
import threading

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
        from core.setup.interlock_setting import create_default_interlock_settings
        from core.views.mixins.ldap_settings import SettingsViewMixin
        from core.setup.oidc import create_default_oidc_rsa_key
        logger.info("Checking defaults.")

        create_default_superuser()
        create_default_interlock_settings()
        SettingsViewMixin().create_default_preset()
        create_default_oidc_rsa_key()
        logger.info("Core startup complete.")