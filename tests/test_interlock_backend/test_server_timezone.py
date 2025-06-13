from pytest_mock import MockerFixture, MockType
from typing import Union
import pytest
import pytz
import subprocess
from interlock_backend.server_timezone import get_server_timezone
from logging import Logger

MockLogger = Union[MockType, Logger]

@pytest.fixture
def f_pytz_timezones(mocker: MockerFixture) -> None:
	"""Fixture to mock pytz.all_timezones for all tests."""
	mocker.patch.object(pytz, "all_timezones", ["UTC", "America/Buenos_Aires", "Europe/London"])

@pytest.fixture
def f_logger(mocker: MockerFixture):
	return mocker.patch("interlock_backend.server_timezone.logger")

def test_get_server_timezone_timedatectl_success(
	mocker: MockerFixture,
	f_pytz_timezones: None,
	f_logger: MockLogger,
) -> None:
	"""Test successful timedatectl path."""
	m_success_output = mocker.Mock()
	m_success_output.decode.return_value = "Europe/London\n"
	m_subprocess = mocker.patch(
		"interlock_backend.server_timezone.subprocess.check_output",
		return_value=m_success_output,
	)

	result = get_server_timezone()

	m_subprocess.assert_called_once_with(
		"timedatectl show --property=Timezone --value".split(),
		stderr=subprocess.DEVNULL,
	)
	f_logger.info.assert_called_with("Configured timezone: Europe/London")
	assert result == "Europe/London"

@pytest.mark.parametrize(
	"value",
	(
		"/usr/share/zoneinfo/America/Buenos_Aires",
		"/etc/timezone/America/Buenos_Aires",
	),
)
def test_get_server_timezone_timedatectl_fallback_to_localtime(
	mocker: MockerFixture,
	value: str,
	f_pytz_timezones: None,
	f_logger: MockLogger,
) -> None:
	"""Test fallback to /etc/localtime when timedatectl fails."""
	m_subprocess = mocker.patch(
		"interlock_backend.server_timezone.subprocess.check_output",
		side_effect=subprocess.CalledProcessError(1, "cmd"),
	)
	m_os = mocker.patch(
		"os.path.realpath",
		return_value=value
	)

	result = get_server_timezone()

	m_subprocess.assert_called_once()
	m_os.assert_called_once_with("/etc/localtime")
	f_logger.info.assert_called_with("Configured timezone: America/Buenos_Aires")
	assert result == "America/Buenos_Aires"

def test_get_server_timezone_localtime_fallback_to_utc(
	mocker: MockerFixture,
	f_pytz_timezones: None,
	f_logger: MockLogger,
) -> None:
	"""Test fallback to UTC when both timedatectl and localtime fail."""
	m_subprocess = mocker.patch(
		"interlock_backend.server_timezone.subprocess.check_output",
		side_effect=subprocess.CalledProcessError(1, "cmd"),
	)
	m_os = mocker.patch("os.path.realpath", side_effect=OSError)

	result = get_server_timezone()

	assert m_subprocess.call_count == 1
	m_os.assert_called_once_with("/etc/localtime")
	f_logger.info.assert_called_with("Configured timezone: UTC")
	assert result == "UTC"

def test_get_server_timezone_invalid_timezone_fallback(
	mocker: MockerFixture,
	f_pytz_timezones: None,
	f_logger: MockLogger,
) -> None:
	"""Test fallback when detected timezone is invalid."""
	m_timezone = "Invalid/Timezone\n"
	m_success_output = mocker.Mock()
	m_success_output.decode.return_value = m_timezone
	mocker.patch(
		"interlock_backend.server_timezone.subprocess.check_output",
		return_value=m_success_output
	)

	result = get_server_timezone()

	f_logger.warning.assert_called_once_with(
		f"Warning: Detected timezone '{m_timezone.strip()}' is invalid. "
		"Falling back to UTC."
	)
	f_logger.info.assert_called_once_with(
		"Configured timezone: UTC"
	)
	assert result == "UTC"
