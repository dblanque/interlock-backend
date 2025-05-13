########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture
################################################################################

@pytest.fixture
def f_connection(mocker: MockerFixture):
	m_connection = mocker.MagicMock()
	m_connection.add = mocker.MagicMock(return_value=None)
	m_connection.modify = mocker.MagicMock(return_value=None)
	m_connection.delete = mocker.MagicMock(return_value=None)
	m_connection.search = mocker.MagicMock(return_value=None)
	m_connection.result = "result"
	return m_connection
