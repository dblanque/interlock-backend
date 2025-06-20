########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture

################################################################################
from core.serializers.token import TokenRefreshSerializer
from rest_framework.exceptions import AuthenticationFailed


@pytest.fixture
def f_user(mocker: MockerFixture):
	return mocker.Mock()


@pytest.fixture
def f_serializer_instance(mocker: MockerFixture, f_user):
	m_serializer_instance = TokenRefreshSerializer()
	m_serializer_instance.user = f_user
	return m_serializer_instance


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
		m_user_auth_fail_conditions = mocker.patch(
			"core.serializers.token.user_auth_fail_conditions",
			return_value=False,
		)

		with pytest.raises(AuthenticationFailed):
			f_serializer_instance.validate(m_attrs)

		m_validate.assert_called_once_with(m_attrs)
		m_user_auth_fail_conditions.assert_called_once_with(f_user)

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
		m_user_auth_fail_conditions = mocker.patch(
			"core.serializers.token.user_auth_fail_conditions",
			return_value=True,
		)

		result = f_serializer_instance.validate(m_attrs)

		m_validate.assert_called_once_with(m_attrs)
		m_user_auth_fail_conditions.assert_called_once_with(f_user)
		assert result == m_attrs
