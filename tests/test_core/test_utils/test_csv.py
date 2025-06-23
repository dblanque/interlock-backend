########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture

################################################################################
from django.test import TestCase
from core.utils.csv import csv_iterator, PseudoBuffer
from django.db.models import QuerySet


class MockModel:
	def __init__(self, **kwargs):
		for k, v in kwargs.items():
			setattr(self, k, v)

	@classmethod
	def objects(cls):
		return cls

	@classmethod
	def all(cls):
		return [cls(name="test1", value=1), cls(name="test2", value=2)]

	@classmethod
	def none(cls):
		return []

	@classmethod
	def values(cls, *fields):
		return [dict((f, getattr(obj, f)) for f in fields) for obj in cls.all()]


class TestPseudoBuffer(TestCase):
	def test_pseudo_buffer(self):
		buffer = PseudoBuffer()
		test_data = "test,data,here"
		assert buffer.write(test_data) == test_data


class TestCSVIterator:
	def test_writeheader(self):
		"""Test that header is properly yielded"""
		fields = ["field1", "field2"]
		result = list(csv_iterator([], fields))
		assert len(result) == 1
		assert result[0] == ",".join(fields) + "\r\n"

	def test_list_of_dicts(self):
		"""Test with list of dictionaries"""
		data = [
			{"field1": "value1", "field2": "value2", "ignore": "this"},
			{"field1": "value3", "field2": "value4"},
		]
		fields = ["field1", "field2"]
		results = list(csv_iterator(data, fields))

		assert len(results) == 3  # header + 2 rows
		assert results[0] == "field1,field2\r\n"
		assert results[1] == "value1,value2\r\n"
		assert results[2] == "value3,value4\r\n"

	def test_list_with_invalid_item(self):
		"""Test TypeError is raised for non-dict items"""
		data = [{"valid": "dict"}, "not-a-dict", {"another": "valid"}]
		with pytest.raises(
			TypeError, match="item in list should be a dictionary"
		):
			list(csv_iterator(data, ["field"]))

	def test_queryset_mock(self, mocker: MockerFixture):
		"""Test with mocked Django queryset"""
		mock_qs = mocker.Mock(spec=QuerySet)
		mock_qs.values.return_value = [
			{"name": "test1", "value": 1},
			{"name": "test2", "value": 2},
		]

		fields = ["name", "value"]
		results = list(csv_iterator(mock_qs, fields))

		assert len(results) == 3  # header + 2 rows
		assert results[0] == "name,value\r\n"
		assert "test1,1" in results[1]
		assert "test2,2" in results[2]
		mock_qs.values.assert_called_once_with(*fields)

	def test_queryset_values_mock(self):
		"""Test with already converted queryset.values()"""
		mock_values = [{"name": "test1"}, {"name": "test2"}]
		fields = ["name"]
		results = list(csv_iterator(mock_values, fields))

		assert len(results) == 3  # header + 2 rows
		assert results[0] == "name\r\n"
		assert "test1" in results[1]
		assert "test2" in results[2]

	def test_field_filtering(self):
		"""Test only specified fields are included"""
		data = [{"keep": "this", "ignore": "this"}]
		results = list(csv_iterator(data, ["keep"]))

		assert len(results) == 2
		assert results[0] == "keep\r\n"
		assert results[1] == "this\r\n"
		assert "ignore" not in results[1]

	def test_empty_list(self):
		"""Test with empty list input"""
		results = list(csv_iterator([], ["field"]))
		assert len(results) == 1  # just header
		assert results[0] == "field\r\n"

	def test_empty_queryset_mock(self, mocker: MockerFixture):
		"""Test with empty mocked queryset"""
		mock_qs = mocker.Mock(spec=QuerySet)
		mock_qs.values.return_value = []

		results = list(csv_iterator(mock_qs, ["field"]))
		assert len(results) == 1  # just header
		assert results[0] == "field\r\n"

	def test_special_characters(self):
		"""Test handling of special CSV characters"""
		data = [{"field,1": 'val"ue', "field2": "line\nbreak"}]
		fields = ["field,1", "field2"]
		results = list(csv_iterator(data, fields))

		# Should properly escape special chars
		assert len(results) == 2
		assert '"field,1"' in results[0]  # quoted header
		assert 'val""ue' in results[1]  # double-quote escaping

	def test_non_string_values(self):
		"""Test non-string values are converted to strings"""
		data = [{"int": 42, "float": 3.14, "bool": True, "none": None}]
		fields = ["int", "float", "bool", "none"]
		results = list(csv_iterator(data, fields))[1]  # get first row

		assert "42" in results
		assert "3.14" in results
		assert "True" in results
		assert "" in results  # None becomes empty string
