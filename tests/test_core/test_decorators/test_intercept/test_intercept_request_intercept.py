import pytest
from core.decorators.intercept import request_intercept
from django.http.request import HttpRequest
from django.http.cookie import SimpleCookie
from core.models.user import User
from rest_framework_simplejwt.tokens import RefreshToken
from interlock_backend.settings import SIMPLE_JWT
from pytest_mock import MockType
from typing import Union

_ACCESS_NAME = SIMPLE_JWT["AUTH_COOKIE_NAME"]
_REFRESH_NAME = SIMPLE_JWT["REFRESH_COOKIE_NAME"]
_JWT_SAMESITE = SIMPLE_JWT["AUTH_COOKIE_SAME_SITE"]
_JWT_SECURE = SIMPLE_JWT["AUTH_COOKIE_SECURE"]


@pytest.fixture
def mock_request(mocker):
	user = User(
		username="test_intercept",
		email="testic@example.com",
		password="MockPassword",
		is_staff=True,
		is_superuser=False,
	)
	user.save()
	request: Union[HttpRequest, MockType] = mocker.Mock(spec=HttpRequest)
	request.user = user
	request.query_params = {"param": "value"}
	request.data = {"key": "value"}
	refresh = RefreshToken.for_user(user)

	request.COOKIES = {}
	request.COOKIES[_ACCESS_NAME] = SimpleCookie(str(refresh.access_token))
	request.COOKIES[_REFRESH_NAME] = SimpleCookie(str(refresh))
	return request


@pytest.mark.django_db
@pytest.mark.parametrize(
	"is_factory",
	(
		True,
		False,
	),
	ids=("As Decorator Factory", "As Decorator"),
)
def test_request_intercept(is_factory, mock_request, logger_path, mocker):
	m_logger = mocker.patch(logger_path)
	m_view_func = mocker.Mock(return_value="response")
	if is_factory is True:
		decorated_func = request_intercept(m_view_func)
	else:
		decorated_func = request_intercept()(m_view_func)
	result = decorated_func(None, mock_request)

	# Verify logger was called with expected messages
	m_logger.info.assert_any_call(mock_request)
	m_logger.info.assert_any_call(mock_request.user)
	m_logger.info.assert_any_call(mock_request.query_params)
	m_logger.info.assert_any_call(mock_request.data)

	# Verify view function was called with correct arguments
	m_view_func.assert_called_once_with(None, mock_request)

	# Verify result is correct
	assert result == "response"


def test_request_intercept_no_query_params_or_data(
	mock_request, logger_path, mocker
):
	del mock_request.query_params
	del mock_request.data
	m_logger = mocker.patch(logger_path)
	mock_view_func = mocker.Mock(return_value="response")
	decorated_func = request_intercept(mock_view_func)
	result = decorated_func(None, mock_request)

	# Verify logger was called with the expected messages
	m_logger.info.assert_any_call(mock_request)
	m_logger.info.assert_any_call(mock_request.user)
	m_logger.info.assert_any_call("No query params.")
	m_logger.info.assert_any_call("No data.")

	# Verify view function was called with the correct arguments
	mock_view_func.assert_called_once_with(None, mock_request)

	# Verify result is correct
	assert result == "response"
