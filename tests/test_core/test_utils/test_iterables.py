########################### Standard Pytest Imports ############################
import pytest

################################################################################
from core.utils.iterables import (
	flatten_list,
	is_non_str_iterable,
	recursive_dict_find,
)


class TestFlattenList:
	@staticmethod
	def test_flatten():
		assert flatten_list([["a", "b"], ["c", "d"]]) == ["a", "b", "c", "d"]


class TestRecursiveDictFind:
	@staticmethod
	def test_find_top_level_key():
		test_dict = {"a": 1, "b": 2, "c": 3}
		assert recursive_dict_find(test_dict, "b") == 2

	@staticmethod
	def test_find_nested_key():
		test_dict = {"a": 1, "b": {"c": 2, "d": {"e": 3}}}
		assert recursive_dict_find(test_dict, "e") == 3

	def test_key_not_found(self):
		test_dict = {"a": 1, "b": 2}
		assert recursive_dict_find(test_dict, "c") is None

	def test_empty_dict(self):
		assert recursive_dict_find({}, "a") is None


class TestIsNonStrIterable:
	@staticmethod
	@pytest.mark.parametrize(
		"value,expected",
		[
			([1, 2, 3], True),
			({"a": 1}, True),
			((1, 2), True),
			({1, 2}, True),
			("string", False),
			(123, False),
			(True, False),
			(None, False),
		],
	)
	def test_various_types(value, expected):
		assert is_non_str_iterable(value) == expected
