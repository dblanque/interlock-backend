import pytest
from pytest_mock import MockerFixture

@pytest.fixture(autouse=True)
def set_debug_off(mocker: MockerFixture):
	mocker.patch("interlock_backend.settings.DEBUG", False)
