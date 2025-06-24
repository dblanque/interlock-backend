################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: interlock_backend.utils
# Contains generic utilities for Interlock

# ---------------------------------- IMPORTS --------------------------------- #
from typing import overload, Any

_local_django_settings = None
try:
	# Add conditional to check if its not mock patched
	if not _local_django_settings:
		from interlock_backend import (
			local_django_settings as _local_django_settings,
		)
except ImportError:  # pragma: no cover
	pass
################################################################################


@overload
def load_override(target_globals, key: str) -> None: ...
@overload
def load_override(target_globals, key: str, default: Any) -> None: ...
def load_override(target_globals, key: str, *args: Any, **kwargs: Any) -> None:
	"""Override a global variable if it exists in local_django_settings.

	Args:
		key: Name of the variable to override
		default: Fallback value if the variable doesn't exist
	"""
	# Check if default was provided (positional or keyword)
	default_provided = "default" in kwargs or len(args) > 0

	if _local_django_settings is not None and hasattr(
		_local_django_settings, key
	):
		target_globals[key] = getattr(_local_django_settings, key)
	elif default_provided:
		# Use provided default (could be None)
		target_globals[key] = kwargs.get("default", args[0] if args else None)
