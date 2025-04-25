########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
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

class TestInsert:
	@staticmethod
	def test_record_not_in_request(admin_user_client: APIClient):
		response: Response = admin_user_client.post("/api/ldap/record/insert/", data={})
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data["code"] == "dns_record_not_in_request"

	@staticmethod
	def test_successful(mocker: MockerFixture, admin_user_client: APIClient):
		m_request_record = {"some_record_attr":"some_value"}
		m_valid_record = {"some_record_attr":"some_value"}
		m_return_record = {"some_record_result":"some_value"}
		m_validate_record = mocker.Mock(return_value=m_valid_record)
		m_create_record = mocker.Mock(return_value=m_return_record)

		mocker.patch.object(LDAPRecordViewSet, "validate_record", m_validate_record)
		mocker.patch.object(LDAPRecordViewSet, "create_record", m_create_record)
		response: Response = admin_user_client.post(
			"/api/ldap/record/insert/", 
			data={"record": m_request_record},
			format="json"
		)
		m_validate_record.assert_called_once_with(record_data=m_request_record)
		m_create_record.assert_called_once_with(record_data=m_valid_record)
		assert response.status_code == status.HTTP_200_OK
		assert response.data["data"] == m_return_record
