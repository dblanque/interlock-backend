########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture, MockType
################################################################################
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from core.views.ldap.group import LDAPGroupsViewSet
from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework import status

@pytest.fixture(autouse=True)
def f_ldap_connector(g_ldap_connector) -> MockType:
	"""Fixture to mock LDAPConnector and its context manager."""
	return g_ldap_connector(patch_path="core.views.ldap.group.LDAPConnector")

@pytest.fixture
def f_runtime_settings(
	mocker: MockerFixture,
	g_runtime_settings: RuntimeSettingsSingleton
):
	mocker.patch("core.views.ldap.group.RuntimeSettings", g_runtime_settings)
	return g_runtime_settings

@pytest.fixture(autouse=True)
def f_interlock_ldap_enabled(g_interlock_ldap_enabled):
	return g_interlock_ldap_enabled

class TestList:
	endpoint = "/api/ldap/groups/"

	def test_success(self, mocker: MockerFixture, admin_user_client: APIClient):
		m_list_groups = mocker.patch.object(
			LDAPGroupsViewSet,
			"list_groups",
			return_value=("data","valid_attributes",)
		)
		response: Response = admin_user_client.get(self.endpoint)
		m_list_groups.assert_called_once()
		assert response.status_code == status.HTTP_200_OK
		assert response.data.get("groups") == "data"
		assert response.data.get("headers") == "valid_attributes"

class TestFetch:
	endpoint = "/api/ldap/groups/fetch/"

	def test_raises_no_dn(self, mocker: MockerFixture, admin_user_client: APIClient):
		mocker.patch.object(LDAPGroupsViewSet, "fetch_group")
		response: Response = admin_user_client.post(self.endpoint, data={})
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("code") == "group_dn_missing"

	def test_success(self, mocker: MockerFixture, admin_user_client: APIClient):
		mocker.patch.object(
			LDAPGroupsViewSet,
			"fetch_group",
			return_value=("group_dict", "headers"))
		response: Response = admin_user_client.post(self.endpoint, data={
			"group":"mock_dn"
		})
		assert response.status_code == status.HTTP_200_OK
		assert response.data.get("data") == "group_dict"
		assert response.data.get("headers") == "headers"

class TestInsert:
	endpoint = "/api/ldap/groups/insert/"
	
	def test_no_group_data_raises(self, mocker: MockerFixture, admin_user_client: APIClient):
		mocker.patch.object(LDAPGroupsViewSet, "create_group")
		response: Response = admin_user_client.post(self.endpoint, data={})
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("detail") == 'group dict is required'

	def test_no_group_cn_raises(self, mocker: MockerFixture, admin_user_client: APIClient):
		mocker.patch.object(LDAPGroupsViewSet, "create_group")
		response: Response = admin_user_client.post(
			self.endpoint,
			data={"group":{"some":"key"}},
			format="json"
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("detail") == "group dict should have a cn key containing the Group Common Name."

	def test_success(self, mocker: MockerFixture, admin_user_client: APIClient):
		mocker.patch.object(LDAPGroupsViewSet, "create_group")
		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				"group": {
					"cn": "mock_cn"
				}
			},
			format="json"
		)
		assert response.status_code == status.HTTP_200_OK

class TestUpdate:
	endpoint = "/api/ldap/groups/update/"

	def test_no_group_data_raises(self, mocker: MockerFixture, admin_user_client: APIClient):
		mocker.patch.object(LDAPGroupsViewSet, "update_group")
		response: Response = admin_user_client.put(self.endpoint, data={})
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("detail") == 'group dict is required'

	def test_success(self, mocker: MockerFixture, admin_user_client: APIClient):
		mocker.patch.object(LDAPGroupsViewSet, "update_group")
		response: Response = admin_user_client.put(
			self.endpoint,
			data={"group":{"mock":"dict"}},
			format="json"
		)
		assert response.status_code == status.HTTP_200_OK

class TestDelete:
	endpoint = "/api/ldap/groups/delete/"
	
	def test_no_group_data_raises(self, mocker: MockerFixture, admin_user_client: APIClient):
		mocker.patch.object(LDAPGroupsViewSet, "delete_group")
		response: Response = admin_user_client.post(self.endpoint, data={})
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("detail") == 'group dict is required'

	def test_success(self, mocker: MockerFixture, admin_user_client: APIClient):
		mocker.patch.object(LDAPGroupsViewSet, "delete_group")
		response: Response = admin_user_client.post(
			self.endpoint,
			data={"group":{"mock":"dict"}},
			format="json"
		)
		assert response.status_code == status.HTTP_200_OK
