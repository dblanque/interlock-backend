########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType
################################################################################
from core.views.mixins.ldap.organizational_unit import OrganizationalUnitMixin

@pytest.fixture
def f_ou_mixin(mocker: MockerFixture):
	m_mixin = OrganizationalUnitMixin()
	m_mixin.ldap_connection = mocker.MagicMock()
	return m_mixin

