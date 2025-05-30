########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType
################################################################################

class TestCreateInfo:
	endpoint = "/api/ldap/application/group/create_info/"
