import pytest
from unittest.mock import patch
from core.decorators.intercept import request_intercept
from rest_framework.request import Request as django_request
from django.contrib.auth.models import User


@pytest.fixture
def mock_request(mocker):
	request = mocker.Mock(spec=django_request)
	request.user = mocker.Mock(spec=User)
	request.query_params = {"param": "value"}
	request.data = {"key": "value"}
	return request


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
