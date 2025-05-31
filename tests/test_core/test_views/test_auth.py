########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType
################################################################################

class TestRefresh:
	endpoint = ""

	def test_get_refresh_access_valid():
		pass
	def test_get_refresh_access_expired():
		pass
	def test_get_refresh_invalid():
		pass

class TestLogout:
	endpoint = ""

	def test_logout_success():
		pass

	def test_logout_token_error():
		pass

	def test_logout_no_token():
		pass