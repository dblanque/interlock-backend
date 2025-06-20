########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture

################################################################################
from rest_framework.serializers import ValidationError
from core.models.setting.base import BaseSetting


def test_clean_raises_validation_error(mocker: MockerFixture):
	mock_instance = mocker.Mock()
	mock_instance.type = None
	with pytest.raises(ValidationError, match="requires type"):
		BaseSetting.clean(mock_instance)


def test_value_setter_raises_validation_error(mocker: MockerFixture):
	mock_instance = mocker.Mock()
	mock_instance.type = None
	with pytest.raises(ValidationError, match="requires type"):
		BaseSetting._value_setter(mock_instance, "some_value")


def test_dunder_str(mocker: MockerFixture):
	mock_instance = mocker.Mock()
	mock_instance.type = "Type"
	mock_instance.value = "Value"
	assert (
		BaseSetting.__str__(mock_instance)
		== f"{mock_instance.type} - {mock_instance.value}"
	)
