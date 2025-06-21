########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture, MockType

################################################################################
from core.models.user import User
from core.serializers.token import (
	TokenObtainPairSerializer,
	TokenRefreshSerializer,
	user_is_not_authenticated,
)
from core.exceptions import otp as exc_otp
from rest_framework.exceptions import AuthenticationFailed
from core.models.choices.log import LOG_ACTION_LOGIN, LOG_CLASS_USER

MODULE = "core.serializers.token"


@pytest.fixture
def f_user(mocker: MockerFixture):
	return mocker.MagicMock()


@pytest.fixture(autouse=True)
def f_log(mocker: MockerFixture):
	return mocker.patch(MODULE + ".DBLogMixin.log")


def test_user_is_not_authenticated_ok(mocker: MockerFixture):
	m_user = mocker.Mock()
	m_user.is_anonymous = False
	m_user.is_enabled = True
	assert not user_is_not_authenticated(m_user)


@pytest.mark.parametrize(
	"anonymous, enabled",
	(
		(True, True),
		(True, False),
		(False, False),
	),
)
def test_user_is_not_authenticated(
	mocker: MockerFixture,
	anonymous: bool,
	enabled: bool,
):
	m_user = mocker.Mock()
	m_user.is_anonymous = anonymous
	m_user.is_enabled = enabled
	assert user_is_not_authenticated(m_user)


class TestTokenObtainPairSerializer:
	@pytest.fixture
	def f_serializer_instance(self, mocker: MockerFixture, f_user):
		m_serializer_instance = TokenObtainPairSerializer()
		m_serializer_instance.user = f_user
		m_serializer_instance.mocked_supers = {
			"validate": mocker.patch(
				"%s.jwt_serializers.TokenObtainSerializer.validate" % (MODULE),
				return_value={},
			)
		}
		m_refresh = mocker.MagicMock(name="mock_refresh_token")
		mocker.patch.object(
			m_serializer_instance,
			"get_token",
			return_value=m_refresh,
		)
		return m_serializer_instance

	def test_raises_authentication_failed(
		self,
		mocker: MockerFixture,
		f_serializer_instance: TokenObtainPairSerializer,
		f_user: User,
	):
		# Mocks
		m_super_validate = f_serializer_instance.mocked_supers["validate"]
		m_user_is_not_authenticated = mocker.patch(
			MODULE + ".user_is_not_authenticated",
			return_value=True,
		)
		m_attrs = {"some": "attrs"}

		# Execution
		with pytest.raises(AuthenticationFailed):
			f_serializer_instance.validate(m_attrs)

		# Assertions
		m_super_validate.assert_called_once_with(
			f_serializer_instance,
			m_attrs,
		)
		f_serializer_instance.get_token.assert_called_once_with(f_user)
		m_user_is_not_authenticated.assert_called_once_with(f_user)

	def test_raises_invalid_recovery(
		self,
		mocker: MockerFixture,
		f_serializer_instance: TokenObtainPairSerializer,
		f_user: User,
	):
		# Mocks
		f_user.recovery_codes = []
		m_super_validate = f_serializer_instance.mocked_supers["validate"]
		m_user_is_not_authenticated = mocker.patch(
			MODULE + ".user_is_not_authenticated",
			return_value=False,
		)
		m_user_has_device = mocker.patch(
			MODULE + ".user_has_device",
			return_value=True,
		)
		m_validate_user_otp = mocker.patch(MODULE + ".validate_user_otp")
		m_attrs = {"recovery_code": "abcd-1234"}

		# Executions
		with pytest.raises(exc_otp.OTPInvalidRecoveryCode):
			f_serializer_instance.validate(m_attrs)

		# Assertions
		m_super_validate.assert_called_once_with(
			f_serializer_instance,
			m_attrs,
		)
		f_serializer_instance.get_token.assert_called_once_with(f_user)
		m_user_is_not_authenticated.assert_called_once_with(f_user)
		m_user_has_device.assert_called_once_with(f_user, confirmed=True)
		m_validate_user_otp.assert_not_called()

	def test_raises_otp_required(
		self,
		mocker: MockerFixture,
		f_serializer_instance: TokenObtainPairSerializer,
		f_user: User,
	):
		# Mocks
		f_user.recovery_codes = []
		m_super_validate = f_serializer_instance.mocked_supers["validate"]
		m_user_is_not_authenticated = mocker.patch(
			MODULE + ".user_is_not_authenticated",
			return_value=False,
		)
		m_user_has_device = mocker.patch(
			MODULE + ".user_has_device",
			return_value=True,
		)
		m_validate_user_otp = mocker.patch(MODULE + ".validate_user_otp")
		m_attrs = {}

		# Execution
		with pytest.raises(exc_otp.OTPRequired):
			f_serializer_instance.validate(m_attrs)

		# Assertions
		m_super_validate.assert_called_once_with(
			f_serializer_instance,
			m_attrs,
		)
		f_serializer_instance.get_token.assert_called_once_with(f_user)
		m_user_is_not_authenticated.assert_called_once_with(f_user)
		m_user_has_device.assert_called_once_with(f_user, confirmed=True)
		m_validate_user_otp.assert_not_called()

	def test_raises_otp_invalid_data(
		self,
		mocker: MockerFixture,
		f_serializer_instance: TokenObtainPairSerializer,
		f_user: User,
	):
		# Mocks
		f_user.recovery_codes = []
		m_super_validate = f_serializer_instance.mocked_supers["validate"]
		m_user_is_not_authenticated = mocker.patch(
			MODULE + ".user_is_not_authenticated",
			return_value=False,
		)
		m_user_has_device = mocker.patch(
			MODULE + ".user_has_device",
			return_value=True,
		)
		m_validate_user_otp = mocker.patch(MODULE + ".validate_user_otp")
		m_attrs = {"totp_code": "123abc"}

		# Execution
		with pytest.raises(exc_otp.OTPInvalidData):
			f_serializer_instance.validate(m_attrs)

		# Assertions
		m_super_validate.assert_called_once_with(
			f_serializer_instance,
			m_attrs,
		)
		f_serializer_instance.get_token.assert_called_once_with(f_user)
		m_user_is_not_authenticated.assert_called_once_with(f_user)
		m_user_has_device.assert_called_once_with(f_user, confirmed=True)
		m_validate_user_otp.assert_not_called()

	def test_success_with_recovery(
		self,
		mocker: MockerFixture,
		f_serializer_instance: TokenObtainPairSerializer,
		f_user: User,
		f_log: MockType,
	):
		# Mocks
		f_user.recovery_codes = [
			"abcd-1234",
		]
		m_super_validate = f_serializer_instance.mocked_supers["validate"]
		m_user_is_not_authenticated = mocker.patch(
			MODULE + ".user_is_not_authenticated",
			return_value=False,
		)
		m_user_has_device = mocker.patch(
			MODULE + ".user_has_device",
			return_value=True,
		)
		m_validate_user_otp = mocker.patch(MODULE + ".validate_user_otp")
		m_attrs = {"recovery_code": "abcd-1234"}

		# Execution
		f_serializer_instance.validate(m_attrs)

		# Assertions
		m_super_validate.assert_called_once_with(
			f_serializer_instance,
			m_attrs,
		)
		f_serializer_instance.get_token.assert_called_once_with(f_user)
		m_user_is_not_authenticated.assert_called_once_with(f_user)
		m_user_has_device.assert_called_once_with(f_user, confirmed=True)
		m_validate_user_otp.assert_not_called()
		assert not f_user.recovery_codes
		f_log.assert_called_once_with(
			user=f_user.id,
			operation_type=LOG_ACTION_LOGIN,
			log_target_class=LOG_CLASS_USER,
		)

	def test_success_with_otp(
		self,
		mocker: MockerFixture,
		f_serializer_instance: TokenObtainPairSerializer,
		f_user: User,
		f_log: MockType,
	):
		# Mocks
		m_super_validate = f_serializer_instance.mocked_supers["validate"]
		m_user_is_not_authenticated = mocker.patch(
			MODULE + ".user_is_not_authenticated",
			return_value=False,
		)
		m_user_has_device = mocker.patch(
			MODULE + ".user_has_device",
			return_value=True,
		)
		m_validate_user_otp = mocker.patch(MODULE + ".validate_user_otp")
		m_attrs = {"totp_code": 123456}

		# Execution
		f_serializer_instance.validate(m_attrs)

		# Assertions
		m_super_validate.assert_called_once_with(
			f_serializer_instance,
			m_attrs,
		)
		f_serializer_instance.get_token.assert_called_once_with(f_user)
		m_user_is_not_authenticated.assert_called_once_with(f_user)
		m_user_has_device.assert_called_once_with(f_user, confirmed=True)
		m_validate_user_otp.assert_called_once_with(user=f_user, data=m_attrs)
		f_log.assert_called_once_with(
			user=f_user.id,
			operation_type=LOG_ACTION_LOGIN,
			log_target_class=LOG_CLASS_USER,
		)

	def test_success_with_otp(
		self,
		mocker: MockerFixture,
		f_serializer_instance: TokenObtainPairSerializer,
		f_user: User,
		f_log: MockType,
	):
		# Mocks
		m_super_validate = f_serializer_instance.mocked_supers["validate"]
		m_user_is_not_authenticated = mocker.patch(
			MODULE + ".user_is_not_authenticated",
			return_value=False,
		)
		m_user_has_device = mocker.patch(
			MODULE + ".user_has_device",
			return_value=True,
		)
		m_validate_user_otp = mocker.patch(MODULE + ".validate_user_otp")
		m_attrs = {"totp_code": 123456}

		# Execution
		f_serializer_instance.validate(m_attrs)

		# Assertions
		m_super_validate.assert_called_once_with(
			f_serializer_instance,
			m_attrs,
		)
		f_serializer_instance.get_token.assert_called_once_with(f_user)
		m_user_is_not_authenticated.assert_called_once_with(f_user)
		m_user_has_device.assert_called_once_with(f_user, confirmed=True)
		m_validate_user_otp.assert_called_once_with(user=f_user, data=m_attrs)
		f_log.assert_called_once_with(
			user=f_user.id,
			operation_type=LOG_ACTION_LOGIN,
			log_target_class=LOG_CLASS_USER,
		)

	@pytest.mark.parametrize(
		"is_superuser",
		(
			True,
			False,
		),
	)
	def test_success(
		self,
		mocker: MockerFixture,
		f_serializer_instance: TokenObtainPairSerializer,
		f_user: User,
		f_log: MockType,
		is_superuser: bool,
	):
		# Mocks
		f_user.is_superuser = is_superuser
		m_super_validate = f_serializer_instance.mocked_supers["validate"]
		m_user_is_not_authenticated = mocker.patch(
			MODULE + ".user_is_not_authenticated",
			return_value=False,
		)
		m_user_has_device = mocker.patch(
			MODULE + ".user_has_device",
			return_value=False,
		)
		m_validate_user_otp = mocker.patch(MODULE + ".validate_user_otp")
		m_attrs = {}

		# Execution
		result = f_serializer_instance.validate(m_attrs)

		# Assertions
		for k in (
			"first_name",
			"last_name",
			"email",
			"user_type",
		):
			assert result[k] == getattr(f_user, k)
		if is_superuser:
			assert result["admin_allowed"]
		else:
			assert "admin_allowed" not in result
		m_super_validate.assert_called_once_with(
			f_serializer_instance,
			m_attrs,
		)
		f_serializer_instance.get_token.assert_called_once_with(f_user)
		m_user_is_not_authenticated.assert_called_once_with(f_user)
		m_user_has_device.assert_called_once_with(f_user, confirmed=True)
		m_validate_user_otp.assert_not_called()
		f_log.assert_called_once_with(
			user=f_user.id,
			operation_type=LOG_ACTION_LOGIN,
			log_target_class=LOG_CLASS_USER,
		)


class TestTokenRefreshSerializer:
	@pytest.fixture
	def f_serializer_instance(mocker: MockerFixture, f_user):
		m_serializer_instance = TokenRefreshSerializer()
		m_serializer_instance.user = f_user
		return m_serializer_instance

	def test_validate_raises_auth_failed(
		self,
		mocker: MockerFixture,
		f_serializer_instance: TokenRefreshSerializer,
		f_user,
	):
		m_attrs = {"some": "attrs"}
		m_validate = mocker.patch(
			"core.serializers.token.jwt_serializers.TokenRefreshSerializer.validate",
			return_value=m_attrs,
		)
		m_user_is_not_authenticated = mocker.patch(
			"core.serializers.token.user_is_not_authenticated",
			return_value=True,
		)

		with pytest.raises(AuthenticationFailed):
			f_serializer_instance.validate(m_attrs)

		m_validate.assert_called_once_with(m_attrs)
		m_user_is_not_authenticated.assert_called_once_with(f_user)

	def test_validate(
		self,
		mocker: MockerFixture,
		f_serializer_instance: TokenRefreshSerializer,
		f_user,
	):
		m_attrs = {"some": "attrs"}
		m_validate = mocker.patch(
			"core.serializers.token.jwt_serializers.TokenRefreshSerializer.validate",
			return_value=m_attrs,
		)
		m_user_is_not_authenticated = mocker.patch(
			"core.serializers.token.user_is_not_authenticated",
			return_value=False,
		)

		result = f_serializer_instance.validate(m_attrs)

		m_validate.assert_called_once_with(m_attrs)
		m_user_is_not_authenticated.assert_called_once_with(f_user)
		assert result == m_attrs
