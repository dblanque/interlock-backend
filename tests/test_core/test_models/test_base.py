########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture
################################################################################
from core.models.base import BaseModel

def test_dunder_str_no_name(mocker: MockerFixture):
	mock_instance = mocker.Mock()
	delattr(mock_instance, "name")
	with pytest.raises(TypeError):
		BaseModel.__str__(mock_instance)

def test_dunder_str_with_name(mocker: MockerFixture):
	mock_instance = mocker.Mock()
	mock_instance.name = "some_name"
	assert BaseModel.__str__(mock_instance) == mock_instance.name
