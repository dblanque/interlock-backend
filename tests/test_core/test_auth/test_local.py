########################### Standard Pytest Imports ############################
from pytest_mock import MockerFixture
################################################################################
from core.auth.local import EmailAuthBackend
from django.core.exceptions import ObjectDoesNotExist

class TestEmailAuthBackend:
	auth_instance = EmailAuthBackend()

	class TestAuthenticate:
		def test_success(self, mocker: MockerFixture):
			m_user = mocker.Mock()
			m_user_cls = mocker.Mock()
			m_user_cls.objects.get.return_value = m_user
			mocker.patch(
				"core.auth.local.get_user_model",
				return_value=m_user_cls
			)
			m_user.check_password.return_value = True
			result = TestEmailAuthBackend.auth_instance.authenticate(
				request=None,
				username="testuser",
				password="mock_password",
			)
			m_user.check_password.assert_called_once_with("mock_password")
			assert result == m_user

		def test_auth_fails(self, mocker: MockerFixture):
			m_user = mocker.Mock()
			m_user_cls = mocker.Mock()
			m_user_cls.objects.get.return_value = m_user
			mocker.patch(
				"core.auth.local.get_user_model",
				return_value=m_user_cls
			)
			m_user.check_password.return_value = False
			result = TestEmailAuthBackend.auth_instance.authenticate(
				request=None,
				username="testuser",
				password="mock_password",
			)
			m_user.check_password.assert_called_once_with("mock_password")
			assert result is None

		def test_user_does_not_exist(self, mocker: MockerFixture):
			m_user = mocker.Mock()
			m_user_cls = mocker.Mock()
			m_user_cls.DoesNotExist = ObjectDoesNotExist
			m_user_cls.objects.get.side_effect = m_user_cls.DoesNotExist
			mocker.patch(
				"core.auth.local.get_user_model",
				return_value=m_user_cls
			)
			m_user.check_password.return_value = False
			result = TestEmailAuthBackend.auth_instance.authenticate(
				request=None,
				username="testuser",
				password="mock_password",
			)
			m_user.check_password.assert_not_called()
			assert result is None

	class TestGetUser:
		def test_success(self, mocker: MockerFixture):
			m_user = mocker.Mock()
			m_user_cls = mocker.Mock()
			m_user_cls.objects.get.return_value = m_user
			mocker.patch(
				"core.auth.local.get_user_model",
				return_value=m_user_cls
			)
			result = TestEmailAuthBackend.auth_instance.get_user(1)
			m_user_cls.objects.get.assert_called_once_with(pk=1)
			assert result == m_user

		def test_returns_none(self, mocker: MockerFixture):
			m_user = mocker.Mock()
			m_user_cls = mocker.Mock()
			m_user_cls.DoesNotExist = ObjectDoesNotExist
			m_user_cls.objects.get.side_effect = m_user_cls.DoesNotExist
			mocker.patch(
				"core.auth.local.get_user_model",
				return_value=m_user_cls
			)
			result = TestEmailAuthBackend.auth_instance.get_user(1)
			m_user_cls.objects.get.assert_called_once_with(pk=1)
			assert result is None