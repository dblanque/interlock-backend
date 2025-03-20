from core.decorators.intercept import intercept
from pytest_mock import MockType


def test_intercept(logger_path, mocker):
	m_logger = mocker.patch(logger_path)
	m_func: MockType = mocker.Mock(return_value="response")
	decorated_func = intercept()(m_func)

	result = decorated_func("arg1", "arg2", key1="value1", key2="value2")

	m_logger.info.assert_any_call(("arg1", "arg2"))
	m_logger.info.assert_any_call({"key1": "value1", "key2": "value2"})

	m_func.assert_called_once_with("arg1", "arg2", key1="value1", key2="value2")

	assert result == "response"
