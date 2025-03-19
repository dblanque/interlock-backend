import pytest
from unittest.mock import MagicMock

@pytest.fixture
def m_connection(mocker) -> MagicMock:
	return mocker.MagicMock()
