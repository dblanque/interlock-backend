################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: interlock_backend.utils
# ---------------------------------- IMPORTS --------------------------------- #
from typing import Any, Dict
from pytest_mock import MockerFixture
import pytest

# Import the module containing load_override
from interlock_backend.utils import load_override

################################################################################
TargetGlobalsType = Dict[str, Any]


class TestLoadOverride:
	"""Test suite for the load_override utility function."""

	def test_overrides_value_when_key_exists_in_local_settings(
		self, mocker: MockerFixture
	) -> None:
		"""Test that load_override correctly overrides when key exists."""
		# Setup
		g_mock_settings = mocker.MagicMock()
		g_mock_settings.TEST_KEY = "test_value"
		mocker.patch(
			"interlock_backend.utils._local_django_settings",
			g_mock_settings,
		)

		target_globals: TargetGlobalsType = {"TEST_KEY": "original_value"}

		# Execute
		load_override(target_globals, "TEST_KEY")

		# Verify
		assert target_globals["TEST_KEY"] == "test_value"

	def test_uses_default_when_key_missing_in_local_settings(
		self, mocker: MockerFixture
	) -> None:
		"""Test that load_override uses default when key doesn't exist."""
		# Setup
		g_mock_settings = mocker.MagicMock(
			spec=[]
		)  # Disable automatic attr creation with spec=[]
		mocker.patch(
			"interlock_backend.utils._local_django_settings",
			g_mock_settings,
		)

		target_globals: TargetGlobalsType = {"TEST_KEY": "original_value"}

		# Execute
		load_override(target_globals, "TEST_KEY", default="default_value")

		# Verify
		assert target_globals["TEST_KEY"] == "default_value"

	def test_preserves_value_when_no_local_settings_and_no_default(
		self, mocker: MockerFixture
	) -> None:
		"""Test that load_override preserves original when no settings/default."""
		# Setup
		mocker.patch("interlock_backend.utils._local_django_settings", None)

		target_globals: TargetGlobalsType = {"TEST_KEY": "original_value"}

		# Execute
		load_override(target_globals, "TEST_KEY")

		# Verify
		assert target_globals["TEST_KEY"] == "original_value"

	def test_handles_positional_default_argument(
		self, mocker: MockerFixture
	) -> None:
		"""Test that load_override works with positional default argument."""
		# Setup
		mocker.patch("interlock_backend.utils._local_django_settings", None)

		target_globals: TargetGlobalsType = {"TEST_KEY": "original_value"}

		# Execute
		load_override(target_globals, "TEST_KEY", "positional_default")

		# Verify
		assert target_globals["TEST_KEY"] == "positional_default"

	def test_handles_keyword_default_argument(
		self, mocker: MockerFixture
	) -> None:
		"""Test that load_override works with keyword default argument."""
		# Setup
		mocker.patch("interlock_backend.utils._local_django_settings", None)

		target_globals: TargetGlobalsType = {"TEST_KEY": "original_value"}

		# Execute
		load_override(target_globals, "TEST_KEY", default="keyword_default")

		# Verify
		assert target_globals["TEST_KEY"] == "keyword_default"

	def test_handles_none_as_valid_default_value(
		self, mocker: MockerFixture
	) -> None:
		"""Test that load_override accepts None as a valid default value."""
		# Setup
		mocker.patch("interlock_backend.utils._local_django_settings", None)

		target_globals: TargetGlobalsType = {"TEST_KEY": "original_value"}

		# Execute
		load_override(target_globals, "TEST_KEY", default=None)

		# Verify
		assert target_globals["TEST_KEY"] is None

	def test_does_not_modify_globals_when_key_missing_and_no_default(
		self, mocker: MockerFixture
	) -> None:
		"""Test that globals remain unchanged when key missing and no default."""
		# Setup
		g_mock_settings = mocker.MagicMock(
			spec=[]
		)  # Disable automatic attr creation with spec=[]
		mocker.patch(
			"interlock_backend.utils._local_django_settings",
			g_mock_settings,
		)

		target_globals: TargetGlobalsType = {"OTHER_KEY": "unchanged_value"}

		# Execute
		load_override(target_globals, "MISSING_KEY")

		# Verify
		assert "MISSING_KEY" not in target_globals
		assert target_globals["OTHER_KEY"] == "unchanged_value"

	def test_works_when_local_django_settings_not_importable(
		self, mocker: MockerFixture
	) -> None:
		"""Test behavior when local_django_settings cannot be imported."""
		# Setup
		mocker.patch(
			"interlock_backend.utils._local_django_settings",
			None,
		)

		target_globals: TargetGlobalsType = {"TEST_KEY": "original_value"}

		# Execute
		load_override(target_globals, "TEST_KEY", default="fallback_value")

		# Verify
		assert target_globals["TEST_KEY"] == "fallback_value"
