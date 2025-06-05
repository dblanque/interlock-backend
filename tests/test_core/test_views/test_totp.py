########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType
################################################################################
from tests.test_core.test_views.conftest import BaseViewTestClass, UserFactory
from core.models.user import User
from rest_framework.response import Response
from rest_framework.test import APIClient
from rest_framework import status
from core.exceptions import otp as exc_otp
from core.constants.attrs.local import LOCAL_ATTR_USERNAME
from core.views.mixins.totp import (
	create_device_totp_for_user,
	set_interlock_otp_label,
)
from django_otp.oath import TOTP
from django_otp.plugins.otp_totp.models import TOTPDevice
from typing import Protocol
from core.models.choices.log import (
	LOG_ACTION_DELETE,
	LOG_CLASS_USER,
	LOG_EXTRA_TOTP_DELETE,
)
import binascii

class TotpDeviceFactory(Protocol):
	def __call__(self, user, **kwargs) -> tuple[TOTPDevice, str]: ...

@pytest.fixture
def f_log(mocker: MockerFixture):
	return mocker.patch("core.views.totp.DBLogMixin.log")

@pytest.fixture
def fc_totp_device() -> TotpDeviceFactory:
	def maker(user, **kwargs):
		assert not TOTPDevice.objects.filter(user=user).exists()

		totp_uri = create_device_totp_for_user(user)
		qs = TOTPDevice.objects.filter(user=user)
		assert qs.count() == 1
		totp_device = qs.first()

		for kw, kw_v in kwargs.items():
			setattr(totp_device, kw, kw_v)
		totp_device.save()

		return totp_device, totp_uri
	return maker

class TestList(BaseViewTestClass):
	_endpoint = "totp-list"

	def test_success_mocked(
		self,
		mocker: MockerFixture,
		admin_user: User,
		admin_user_client: APIClient,
	):
		m_totp_device = mocker.Mock(name="m_totp_device")
		m_totp_device.config_url = "mock_url"
		m_totp_device.confirmed = True
		m_get_totp_fn = mocker.patch(
			"core.views.totp.get_user_totp_device",
			return_value=m_totp_device,
		)
		m_set_label_fn = mocker.patch(
			"core.views.totp.set_interlock_otp_label",
			return_value="mock_totp_uri"
		)

		response: Response = admin_user_client.get(self.endpoint)
		assert response.status_code == status.HTTP_200_OK
		m_get_totp_fn.assert_called_once_with(admin_user)
		m_set_label_fn.assert_called_once_with(
			url=m_totp_device.config_url,
			user=admin_user,
		)

	def test_success_mock_label_replace(
		self,
		mocker: MockerFixture,
		admin_user: User,
		admin_user_client: APIClient,
		fc_totp_device: TotpDeviceFactory,
	):
		totp_device, totp_uri = fc_totp_device(admin_user)

		m_set_label_fn = mocker.patch(
			"core.views.totp.set_interlock_otp_label",
			return_value="mock_totp_uri"
		)

		response: Response = admin_user_client.get(self.endpoint)
		assert response.status_code == status.HTTP_200_OK
		m_set_label_fn.assert_called_once_with(
			url=totp_device.config_url,
			user=admin_user,
		)

	def test_success(
		self,
		admin_user: User,
		admin_user_client: APIClient,
		fc_totp_device: TotpDeviceFactory,
	):
		totp_device, totp_uri = fc_totp_device(admin_user)

		response: Response = admin_user_client.get(self.endpoint)
		response_data: dict = response.data
		assert response.status_code == status.HTTP_200_OK
		assert response_data.get("totp_uri") == totp_uri
		assert not response_data.get("totp_confirmed")[0]
		assert len(response_data.get("recovery_codes")) == 5

	def test_success_no_device(
		self,
		admin_user: User,
		admin_user_client: APIClient,
	):
		qs = TOTPDevice.objects.filter(user=admin_user)
		assert not qs.exists()

		response: Response = admin_user_client.get(self.endpoint)
		response_data: dict = response.data
		assert response.status_code == status.HTTP_200_OK
		assert response_data.get("totp_uri") is None
		assert not response_data.get("totp_confirmed")[0]
		assert not response_data.get("recovery_codes")

class TestCreateDevice(BaseViewTestClass):
	_endpoint = "totp-create-device"

	def test_raises_serializer_fail(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
	):
		mocker.patch(
			"core.views.totp.OTPTokenSerializer",
			side_effect=exc_otp.OTPInvalidData,
		)
		response: Response = admin_user_client.get(self.endpoint)
		assert response.status_code == status.HTTP_400_BAD_REQUEST

	def test_success_mocked(
		self,
		mocker: MockerFixture,
		admin_user: User,
		admin_user_client: APIClient,
	):
		m_uri = "mock_uri"
		m_create_device_fn = mocker.patch(
			"core.views.totp.create_device_totp_for_user",
			return_value=m_uri
		)

		response: Response = admin_user_client.get(self.endpoint)
		response_data: dict = response.data

		assert response.status_code == status.HTTP_200_OK
		m_create_device_fn.assert_called_once_with(admin_user)
		assert response_data.get("totp_uri") == m_uri
	
	def test_success(
		self,
		admin_user: User,
		admin_user_client: APIClient,
	):
		qs = TOTPDevice.objects.filter(user=admin_user)
		assert not qs.exists()

		response: Response = admin_user_client.get(self.endpoint)
		response_data: dict = response.data
		admin_user.refresh_from_db()

		qs = TOTPDevice.objects.filter(user=admin_user)
		assert qs.exists()
		totp_device = qs.first()
		assert response.status_code == status.HTTP_200_OK
		assert response_data.get("totp_uri") == set_interlock_otp_label(
			url=totp_device.config_url,
			user=admin_user,
		)
		assert response_data.get("recovery_codes") == admin_user.recovery_codes


class TestValidateDevice(BaseViewTestClass):
	_endpoint = "totp-validate-device"

	def test_successful_validation(
		self,
		admin_user: User,
		admin_user_client: APIClient,
		fc_totp_device: TotpDeviceFactory,
	):
		totp_device, totp_uri = fc_totp_device(admin_user)

		# Generate a valid TOTP code
		totp = TOTP(
			key=binascii.unhexlify(totp_device.key),
            step=totp_device.step,
            digits=totp_device.digits,
            drift=totp_device.tolerance
        )
		valid_code = totp.token()

		response: Response = admin_user_client.post(
			self.endpoint,
			{'totp_code': valid_code},
			format='json',
		)
		response_data: dict = response.data

		assert response.status_code == status.HTTP_200_OK
		assert response_data["code"] == 0
		assert response_data["code_msg"] == "ok"

	def test_raises_on_confirmed_device(
		self,
		admin_user: User,
		admin_user_client: APIClient,
		fc_totp_device: TotpDeviceFactory,
	):
		totp_device, totp_uri = fc_totp_device(admin_user, confirmed=True)

		# Generate a valid TOTP code
		totp = TOTP(
			key=binascii.unhexlify(totp_device.key),
            step=totp_device.step,
            digits=totp_device.digits,
            drift=totp_device.tolerance,
        )
		valid_code = totp.token()

		response: Response = admin_user_client.post(
			self.endpoint,
			{'totp_code': valid_code},
			format='json',
		)

		assert response.status_code == status.HTTP_400_BAD_REQUEST

	def test_invalid_token(
		self,
		admin_user_client: APIClient,
	):
		response: Response = admin_user_client.post(
			self.endpoint,
			{'totp_code': '000000'},  # Invalid code
			format='json',
		)

		assert response.status_code == status.HTTP_400_BAD_REQUEST

	def test_missing_token(
		self,
		admin_user_client: APIClient,
	):
		response: Response = admin_user_client.post(
			self.endpoint,
			{},  # Missing token
			format='json'
		)

		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("code") == "otp_no_device_registered"

class TestDeleteDevice(BaseViewTestClass):
	_endpoint = "totp-delete-device"

	def test_success(
		self,
		admin_user: User,
		admin_user_client: APIClient,
		fc_totp_device: TotpDeviceFactory,
	):
		fc_totp_device(user=admin_user)

		response: Response = admin_user_client.post(self.endpoint)
		assert response.status_code == status.HTTP_200_OK
		assert not TOTPDevice.objects.filter(user=admin_user).exists()

	def test_no_device(
		self,
		admin_user: User,
		admin_user_client: APIClient,
	):
		assert not TOTPDevice.objects.filter(user=admin_user).exists()

		response: Response = admin_user_client.post(self.endpoint)
		assert response.status_code == status.HTTP_200_OK

	def test_mocked(
		self,
		mocker: MockerFixture,
		admin_user: User,
		admin_user_client: APIClient,
	):
		m_delete_device_fn = mocker.patch("core.views.totp.delete_device_totp_for_user")
		response: Response = admin_user_client.post(self.endpoint)
		assert response.status_code == status.HTTP_200_OK
		m_delete_device_fn.assert_called_once_with(admin_user)

class TestDeleteForUser(BaseViewTestClass):
	_endpoint = "totp-delete-for-user"

	def test_success(
		self,
		mocker: MockerFixture,
		user_factory: UserFactory,
		admin_user: User,
		admin_user_client: APIClient,
		fc_totp_device: TotpDeviceFactory,
		f_log: MockType,
	):
		normal_user = user_factory(
			username="normaluser",
			email="normal@example.com",
		)
		totp_device, totp_uri = fc_totp_device(user=normal_user)

		response: Response = admin_user_client.post(
			self.endpoint,
			data={LOCAL_ATTR_USERNAME: normal_user.username},
			format="json",
		)
		assert response.status_code == status.HTTP_200_OK
		assert not TOTPDevice.objects.filter(user=normal_user).exists()
		f_log.assert_called_once_with(
			user=admin_user.id,
			operation_type=LOG_ACTION_DELETE,
			log_target_class=LOG_CLASS_USER,
			log_target=normal_user.username,
			message=LOG_EXTRA_TOTP_DELETE,
		)

	def test_success_without_device(
		self,
		mocker: MockerFixture,
		user_factory: UserFactory,
		admin_user: User,
		admin_user_client: APIClient,
		fc_totp_device: TotpDeviceFactory,
		f_log: MockType,
	):
		normal_user = user_factory(
			username="normaluser",
			email="normal@example.com",
		)
		assert not TOTPDevice.objects.filter(user=normal_user).exists()

		response: Response = admin_user_client.post(
			self.endpoint,
			data={LOCAL_ATTR_USERNAME: normal_user.username},
			format="json",
		)
		assert response.status_code == status.HTTP_200_OK
		f_log.assert_not_called()

	def test_raises_non_existing_user(
		self,
		admin_user_client: APIClient,
	):
		response: Response = admin_user_client.post(
			self.endpoint,
			data={LOCAL_ATTR_USERNAME: "nonexistinguser"},
			format="json",
		)
		assert response.status_code == status.HTTP_404_NOT_FOUND

	def test_raises_missing_keys(
		self,
		admin_user_client: APIClient,
	):
		response: Response = admin_user_client.post(
			self.endpoint,
			data={},
			format="json",
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
