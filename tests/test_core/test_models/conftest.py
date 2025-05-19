########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture, MockType
################################################################################
from typing import Protocol, Union
from core.type_hints.connector import LDAPConnectionProtocol

class LDAPConnectionFactoryProtocol(Protocol):
	def __call__(
		self,
		add: MockType = None,
		modify: MockType = None,
		delete: MockType = None,
		search: MockType = None,
		result: MockType | str = None,
	) -> Union[MockType, LDAPConnectionProtocol]: ...

@pytest.fixture
def fc_connection(mocker: MockerFixture) -> LDAPConnectionFactoryProtocol:
	def maker(*args, **kwargs):
		m_connection = mocker.MagicMock()
		_set_attrs = []
		for kw in kwargs:
			setattr(m_connection, kw, kwargs.pop(kw))
			_set_attrs.append(kw)
		
		for default_fn in ("add", "modify", "delete", "search"):
			if default_fn in _set_attrs:
				continue
			_mock_fn = mocker.MagicMock(return_value=None)
			setattr(m_connection, default_fn, _mock_fn)

		if "result" not in _set_attrs:
			m_connection.result = "result"
		return m_connection
	return maker

@pytest.fixture
def f_connection(fc_connection):
	return fc_connection()