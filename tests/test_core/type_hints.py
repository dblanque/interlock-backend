from core.ldap.connector import LDAPConnector
from pytest_mock import MockType
from typing import Union

class LDAPConnectorMockContextProtocol:
	cxt_manager: MockType
	cls_mock: MockType

LDAPConnectorMock = Union[
	LDAPConnector,
	LDAPConnectorMockContextProtocol,
	MockType,
]