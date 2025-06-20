########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture

################################################################################
from core.serializers.token import (
	TokenRefreshSerializer,
	user_is_not_authenticated,
)
from rest_framework.exceptions import AuthenticationFailed


@pytest.fixture
def f_user(mocker: MockerFixture):
	return mocker.Mock()


@pytest.fixture
def f_serializer_instance(mocker: MockerFixture, f_user):
	m_serializer_instance = TokenRefreshSerializer()
	m_serializer_instance.user = f_user
	return m_serializer_instance


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
	pass


class TestTokenRefreshSerializer:
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
