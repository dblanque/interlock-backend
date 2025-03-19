import pytest
from core.exceptions.base import CoreException  # Replace `your_module` with the actual module name

def test_init_without_data():
    """
    Test that the `detail` attribute is set to default values when `data` is None.
    """
    exception = CoreException()

    # Verify default values
    assert exception.detail == {
        "code": exception.default_code,
        "detail": exception.default_detail,
    }

def test_init_with_data():
    """
    Test that the `detail` attribute is set to the provided data.
    """
    data = {"code": "custom_code", "detail": "custom_detail"}
    exception = CoreException(data=data)

    # Verify the detail is set to the provided data
    assert exception.detail == data

def test_set_detail_with_dict():
    """
    Test that `set_detail` updates the `detail` attribute and ensures `code` and `detail` keys exist.
    """
    exception = CoreException()
    data = {"custom_key": "custom_value"}

    # Call set_detail
    exception.set_detail(data)

    # Verify the detail is updated and contains the required keys
    assert exception.detail == {
        "custom_key": "custom_value",
        "code": exception.default_code,
        "detail": exception.default_detail,
    }

def test_set_detail_with_non_dict():
    """
    Test that `set_detail` sets the `detail` attribute directly when `data` is not a dictionary.
    """
    exception = CoreException()
    data = "non_dict_data"

    # Call set_detail
    exception.set_detail(data)

    # Verify the detail is set directly
    assert exception.detail == data

def test_set_detail_with_partial_dict():
    """
    Test that `set_detail` adds missing keys (`code` and `detail`) when `data` is a partial dictionary.
    """
    exception = CoreException()
    data = {"custom_key": "custom_value"}

    # Call set_detail
    exception.set_detail(data)

    # Verify the detail is updated and contains the required keys
    assert exception.detail == {
        "custom_key": "custom_value",
        "code": exception.default_code,
        "detail": exception.default_detail,
    }

def test_set_detail_with_full_dict():
    """
    Test that `set_detail` does not modify `code` and `detail` keys if they already exist.
    """
    exception = CoreException()
    data = {
        "code": "existing_code",
        "detail": "existing_detail",
        "custom_key": "custom_value",
    }

    # Call set_detail
    exception.set_detail(data)

    # Verify the detail is updated without modifying existing keys
    assert exception.detail == data
