################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# tests/test_core_views_mixins_totp.py

import pytest
import re
from core.views.mixins.totp import (
	get_user_totp_device,
	set_interlock_otp_label,
	generate_recovery_codes,
	create_device_totp_for_user,
	delete_device_totp_for_user,
	fetch_device_totp_for_user,
	validate_user_otp,
	TOTP_WITH_LABEL_RE,
)
from core.exceptions import otp as exc_otp
from django.contrib.auth.models import User
from django_otp.plugins.otp_totp.models import TOTPDevice
from pytest_mock import MockerFixture, MockType
from typing import Union
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton

# ----------------------------------- FIXTURES ---------------------------------#

@pytest.fixture
def f_user(mocker: MockerFixture) -> MockType:
	m_user = mocker.MagicMock(spec=User)
	m_user.id = 1
	m_user.email = None
	m_user.username = "testuser"
	m_user.totpdevice_set = mocker.MagicMock()
	m_user.recovery_codes = []
	m_user.save.return_value = None
	return m_user

@pytest.fixture
def f_device(mocker: MockerFixture, f_user: MockType) -> MockType:
	m_device = mocker.MagicMock(spec=TOTPDevice)
	m_device.config_url = f"otpauth://totp/{f_user.username}?secret=MOCKSECRET&algorithm=SHA1&digits=6&period=30"
	m_device.verify_token.return_value = True
	m_device.confirmed = False
	return m_device

@pytest.fixture
def f_logger(mocker: MockerFixture) -> MockType:
	return mocker.patch("core.views.mixins.totp.logger")

@pytest.fixture(autouse=True)
def f_runtime_settings(
	mocker: MockerFixture,
	g_runtime_settings: RuntimeSettingsSingleton
) -> Union[RuntimeSettingsSingleton, MockType]:
	return mocker.patch(
		"core.views.mixins.totp.RuntimeSettings",
		g_runtime_settings
	)

# -------------------------------- TEST CLASSES --------------------------------#

class TestGetUserTotpDevice:
	@staticmethod
	def test_returns_device_when_exists(
		mocker: MockerFixture,
		f_user: MockType,
		f_device: MockType
	) -> None:
		mocker.patch(
			'core.views.mixins.totp.devices_for_user',
			return_value=[f_device]
		)
		result = get_user_totp_device(f_user)
		assert result == f_device

	@staticmethod
	def test_returns_none_when_no_devices(
		mocker: MockerFixture,
		f_user: MockType
	) -> None:
		mocker.patch(
			'core.views.mixins.totp.devices_for_user',
			return_value=[]
		)
		result = get_user_totp_device(f_user)
		assert result is None

class TestParseConfigUrl:
	@staticmethod
	@pytest.mark.parametrize(
		"add_email",
		(
			True,
			False,
		),
		ids=[
			"With custom email",
			"No Email",
		]
	)
	def test_label_parsing(
		mocker: MockerFixture,
		add_email: bool,
		f_user: MockType,
		f_runtime_settings: RuntimeSettingsSingleton,
		f_device: MockType,
	) -> None:
		m_domain = str(f_runtime_settings.LDAP_DOMAIN)
		m_username = str(f_user.username)
		if add_email:
			expected_ident = "testuser@otherdomain.com"
			f_user.email = expected_ident
		else:
			expected_ident = f"{m_username}@{m_domain}"
		expected_pattern = rf"otpauth://totp/Interlock.*{expected_ident}\?secret=MOCKSECRET.*"
		mocker.patch('core.views.mixins.totp.INTERLOCK_DEBUG', False)

		result = set_interlock_otp_label(f_device.config_url, f_user)

		# 'otpauth://totp/Interlock EXAMPLE:testuser@example.com?secret=MOCKSECRET&algorithm=SHA1&digits=6&period=30'
		assert re.match(expected_pattern, result)

class TestGenerateRecoveryCodes:
	@staticmethod
	def test_generates_correct_amount(mocker: MockerFixture) -> None:
		m_random = mocker.patch('core.views.mixins.totp.random')
		m_random.choice.side_effect = lambda x: 'A'  # Force predictable output
		
		codes = generate_recovery_codes(3)
		assert len(codes) == 3
		assert codes == ["AAAA-AAAA-AAAA"] * 3  # All same due to mocked random

	@staticmethod
	def test_code_format_real_random() -> None:
		codes = generate_recovery_codes(100)
		assert all(
			re.match(r"^[A-Za-z]{4}-[A-Za-z]{4}-[A-Za-z]{4}$", code)
			for code in codes
		)
		assert len(set(codes)) > 1  # Very likely to have duplicates in 100 codes

class TestCreateDeviceTotpForUser:
	@staticmethod
	def test_creates_new_device_when_none_exists(
		mocker: MockerFixture,
		f_user: MockType,
		f_device: MockType,
		f_logger: MockType
	) -> None:
		mocker.patch(
			'core.views.mixins.totp.get_user_totp_device',
			return_value=None
		)
		f_user.totpdevice_set.create.return_value = f_device
		
		create_device_totp_for_user(f_user)

		f_logger.debug.assert_called_once_with(
			"TOTP Device created for user %s", f_user.username)
		f_user.totpdevice_set.create.assert_called_once_with(confirmed=False)
		assert f_user.recovery_codes
		f_user.save.assert_called()

class TestValidateUserOtp:
	@staticmethod
	def test_validates_unconfirmed_device(
		mocker: MockerFixture,
		f_user: MockType,
		f_device: MockType,
		f_logger: MockType
	) -> None:
		mocker.patch(
			'core.views.mixins.totp.get_user_totp_device',
			return_value=f_device
		)
		assert validate_user_otp(f_user, {"totp_code": "123456"}) is True
		assert f_device.confirmed
		f_device.save.assert_called()
		f_logger.debug.assert_called_once_with(
			"TOTP Device newly confirmed for user %s", f_user.username)

	@staticmethod
	def test_validates_confirmed_device(
		mocker: MockerFixture,
		f_user: MockType,
		f_device: MockType,
		f_logger: MockType
	) -> None:
		f_device.confirmed = True
		mocker.patch(
			'core.views.mixins.totp.get_user_totp_device',
			return_value=f_device
		)
		assert validate_user_otp(f_user, {"totp_code": "123456"}) is True
		assert f_device.confirmed
		f_device.save.assert_not_called()
		f_logger.debug.assert_called_once_with(
			"TOTP Device already confirmed for user %s", f_user.username)

	@staticmethod
	def test_raises_when_no_device(
		mocker: MockerFixture,
		f_user: MockType,
		f_logger: MockType
	) -> None:
		mocker.patch(
			'core.views.mixins.totp.get_user_totp_device',
			return_value=None
		)
		with pytest.raises(exc_otp.OTPNoDeviceRegistered):
			validate_user_otp(f_user, {"totp_code": "123456"})
		f_logger.warning.assert_called_once_with(
			"User %s attempted to validate non-existing TOTP Device.", f_user.username)

	@staticmethod
	def test_returns_false(
		mocker: MockerFixture,
		f_user: MockType,
	) -> None:
		mocker.patch(
			'core.views.mixins.totp.get_user_totp_device',
			return_value=None
		)
		assert validate_user_otp(f_user, {"totp_code": "123456"}, False) is False

	@staticmethod
	def test_raises_invalid_code(
		mocker: MockerFixture,
		f_user: MockType,
		f_device: MockType,
		f_logger: MockType
	) -> None:
		f_device.verify_token.return_value = False
		mocker.patch(
			'core.views.mixins.totp.get_user_totp_device',
			return_value=f_device
		)
		with pytest.raises(exc_otp.OTPInvalidCode):
			validate_user_otp(f_user, {"totp_code": "wrong"})
		f_logger.warning.assert_called_once_with(
			"User %s entered invalid TOTP Code.", f_user.username)

class TestDeleteDeviceTotpForUser:
	@staticmethod
	def test_deletes_existing_device(
		mocker: MockerFixture,
		f_user: MockType,
		f_device: MockType,
		f_logger: MockType
	) -> None:
		mocker.patch(
			'core.views.mixins.totp.get_user_totp_device',
			return_value=f_device
		)
		m_totp_device = mocker.patch(
			'core.views.mixins.totp.TOTPDevice.objects.get'
		)
		
		result = delete_device_totp_for_user(f_user)
		
		assert result == m_totp_device.return_value.delete.return_value
		assert f_user.recovery_codes == []
		f_user.save.assert_called()
		f_logger.info.assert_called_once_with(
			"TOTP Device deleted for user %s", f_user.username)

	@staticmethod
	def test_deletes_non_existing_device(
		mocker: MockerFixture,
		f_user: MockType,
	) -> None:
		mocker.patch(
			'core.views.mixins.totp.get_user_totp_device',
			return_value=None
		)

		assert delete_device_totp_for_user(f_user) is True

class TestFetchDeviceTotpForUser:
	@staticmethod
	def test_fetch_returns_none(
		mocker: MockerFixture,
		f_user: MockType,
	):
		mocker.patch("core.views.mixins.totp.get_user_totp_device", return_value=None)
		assert fetch_device_totp_for_user(f_user) is None

	@staticmethod
	def test_fetch_returns_uri(
		mocker: MockerFixture,
		f_user: MockType,
		f_device: MockType
	):
		mocker.patch("core.views.mixins.totp.get_user_totp_device", return_value=f_device)
		assert TOTP_WITH_LABEL_RE.match(fetch_device_totp_for_user(f_user))
