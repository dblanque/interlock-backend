########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType
################################################################################
from tests.test_core.test_views.conftest import BaseViewTestClass

class TestConsent(BaseViewTestClass):
	_endpoint = "oidc-consent"

class TestGet(BaseViewTestClass):
	_endpoint = "oidc-authorize"
