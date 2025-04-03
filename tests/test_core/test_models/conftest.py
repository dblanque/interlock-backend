import pytest


@pytest.fixture
def f_connection(mocker):
	m_connection = mocker.MagicMock()
	m_connection.add = mocker.MagicMock(return_value=None)
	m_connection.modify = mocker.MagicMock(return_value=None)
	m_connection.delete = mocker.MagicMock(return_value=None)
	m_connection.search = mocker.MagicMock(return_value=None)
	m_connection.result = "result"
	return m_connection
