# core/utils/apps_ready.py
import time
from django.apps import apps
from threading import Lock
from logging import getLogger

logger = getLogger()
_init_lock = Lock()
_ready_checked = False


def ensure_apps_ready():
	"""Thread-safe checker that blocks until apps are ready"""
	global _ready_checked

	with _init_lock:
		if _ready_checked:
			return True

		while not apps.ready:
			logger.debug("⌛ Waiting for app registry...")
			time.sleep(0.1)  # Yield control

		_ready_checked = True
		return True
