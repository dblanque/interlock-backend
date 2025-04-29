########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture, MockType
################################################################################
from core.views.ldap.record import LDAPRecordViewSet
from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework import status


@pytest.fixture(autouse=True)
def f_ldap_connector(g_ldap_connector) -> MockType:
	"""Fixture to mock LDAPConnector and its context manager."""
	return g_ldap_connector(patch_path="core.views.ldap.record.LDAPConnector")


@pytest.fixture
def f_viewset():
	return LDAPRecordViewSet()


@pytest.fixture(autouse=True)
def f_interlock_ldap_enabled(g_interlock_ldap_enabled):
	return g_interlock_ldap_enabled


class TestInsert:
	endpoint = "/api/ldap/record/insert/"

	def test_record_not_in_request(self, admin_user_client: APIClient):
		response: Response = admin_user_client.post(
			self.endpoint, data={}
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data["code"] == "dns_record_not_in_request"

	def test_successful(self, mocker: MockerFixture, admin_user_client: APIClient):
		m_request_record = {"some_record_attr": "some_value"}
		m_valid_record = {"some_record_attr": "some_value"}
		m_return_record = {"some_record_result": "some_value"}
		m_validate_record = mocker.Mock(return_value=m_valid_record)
		m_create_record = mocker.Mock(return_value=m_return_record)

		mocker.patch.object(
			LDAPRecordViewSet, "validate_record", m_validate_record
		)
		mocker.patch.object(LDAPRecordViewSet, "create_record", m_create_record)
		response: Response = admin_user_client.post(
			self.endpoint,
			data={"record": m_request_record},
			format="json",
		)
		m_validate_record.assert_called_once_with(record_data=m_request_record)
		m_create_record.assert_called_once_with(record_data=m_valid_record)
		assert response.status_code == status.HTTP_200_OK
		assert response.data["data"] == m_return_record


class TestUpdate:
	endpoint = "/api/ldap/record/update/"

	def test_old_record_not_in_request(self, admin_user_client: APIClient):
		response: Response = admin_user_client.put(
			self.endpoint,
			data={"record": {"some": "record"}},
			format="json",
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data["code"] == "dns_record_not_in_request"

	def test_record_not_in_request(self, admin_user_client: APIClient):
		response: Response = admin_user_client.put(
			self.endpoint,
			data={"old_record": {"some": "record"}},
			format="json",
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data["code"] == "dns_record_not_in_request"

	def test_successful(self, mocker: MockerFixture, admin_user_client: APIClient):
		# Mocked Request Data
		m_request_record = {"some_record_attr": "some_value"}
		m_request_old_record = {"some_record_attr": "some_old_value"}
		# Mocked Validated Data
		m_valid_record = {"some_record_attr": "some_value"}
		m_valid_old_record = {"some_record_attr": "some_old_value"}

		m_result = {"some_record_result": "some_value"}
		m_validate_record = mocker.Mock(
			side_effect=[m_valid_record, m_valid_old_record]
		)
		m_update_record = mocker.Mock(return_value=m_result)

		mocker.patch.object(
			LDAPRecordViewSet, "validate_record", m_validate_record
		)
		mocker.patch.object(LDAPRecordViewSet, "update_record", m_update_record)
		response: Response = admin_user_client.put(
			self.endpoint,
			data={
				"record": m_request_record,
				"oldRecord": m_request_old_record,
			},
			format="json",
		)
		m_validate_record.assert_any_call(record_data=m_request_record)
		m_validate_record.assert_any_call(record_data=m_request_old_record)
		m_validate_record.call_count == 2
		m_update_record.assert_called_once_with(
			record_data=m_valid_record, old_record_data=m_valid_old_record
		)
		assert response.status_code == status.HTTP_200_OK
		assert response.data["data"] == m_result


class TestDelete:
	endpoint = "/api/ldap/record/delete/"
	def test_record_not_in_request(self, admin_user_client: APIClient):
		response: Response = admin_user_client.post(
			self.endpoint, data={}
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data["code"] == "dns_record_not_in_request"

	def test_overlapping_operations_raises(self, admin_user_client: APIClient):
		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				"record": {"some": "record"},
				"records": [{"some": "record"}],
			},
			format="json",
		)
		assert response.status_code == status.HTTP_409_CONFLICT
		assert response.data["code"] == "dns_record_operation_conflict"

	def test_successful_single(
		self,
		mocker: MockerFixture, admin_user_client: APIClient
	):
		m_request_record = {"some_record_attr": "some_value"}
		m_valid_record = {"some_record_attr": "some_value"}
		m_validate_record = mocker.Mock(return_value=m_valid_record)
		m_delete_record = mocker.Mock(return_value="connection_result")

		mocker.patch.object(
			LDAPRecordViewSet, "validate_record", m_validate_record
		)
		mocker.patch.object(LDAPRecordViewSet, "delete_record", m_delete_record)
		response: Response = admin_user_client.post(
			self.endpoint,
			data={"record": m_request_record},
			format="json",
		)
		m_validate_record.assert_called_once_with(record_data=m_request_record)
		m_delete_record.assert_called_once_with(record_data=m_valid_record)
		assert response.status_code == status.HTTP_200_OK
		assert response.data["data"] == "connection_result"

	def test_successful_multi(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
	):
		m_request_record_1 = {"raw_attr_1": "raw_v"}
		m_request_record_2 = {"raw_attr_2": "raw_v"}
		m_valid_record_1 = {"valid_attr_1": "valid_v"}
		m_valid_record_2 = {"valid_attr_2": "valid_v"}
		m_validate_record = mocker.Mock(
			side_effect=[m_valid_record_1, m_valid_record_2]
		)
		m_delete_record = mocker.Mock(
			side_effect=["record_result_1", "record_result_2"]
		)

		mocker.patch.object(
			LDAPRecordViewSet, "validate_record", m_validate_record
		)
		mocker.patch.object(LDAPRecordViewSet, "delete_record", m_delete_record)
		response: Response = admin_user_client.post(
			self.endpoint,
			data={"records": [m_request_record_1, m_request_record_2]},
			format="json",
		)
		m_validate_record.call_count == 2
		m_validate_record.assert_any_call(record_data=m_request_record_1)
		m_validate_record.assert_any_call(record_data=m_request_record_2)
		m_delete_record.call_count == 2
		m_delete_record.assert_any_call(record_data=m_valid_record_1)
		m_delete_record.assert_any_call(record_data=m_valid_record_2)
		assert response.status_code == status.HTTP_200_OK
		assert response.data["data"] == ["record_result_1", "record_result_2"]

	def test_successful_single_raises_malformed(self, admin_user_client: APIClient):
		m_request_record = ["some_record_attr", "some_value"]

		response: Response = admin_user_client.post(
			self.endpoint,
			data={"record": m_request_record},
			format="json",
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data["code"] == "dns_record_data_malformed"

	def test_successful_multi_raises_malformed_parent(
		self,
		admin_user_client: APIClient,
	):
		m_request_records = 1

		response: Response = admin_user_client.post(
			self.endpoint,
			data={"records": m_request_records},
			format="json",
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data["code"] == "dns_record_data_malformed"

	def test_successful_multi_raises_malformed(self, admin_user_client: APIClient):
		m_request_records = ["some_record_attr", "some_value"]

		response: Response = admin_user_client.post(
			self.endpoint,
			data={"records": m_request_records},
			format="json",
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data["code"] == "dns_record_data_malformed"
