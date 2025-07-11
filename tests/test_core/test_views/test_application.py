from pytest_mock import MockerFixture
from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework import status
from core.models.application import Application, ApplicationSecurityGroup
from oidc_provider.models import Client
from core.views.application import ApplicationViewSet
from core.serializers.application import ApplicationSerializer
from tests.test_core.test_views.conftest import (
	BaseViewTestClass,
	BaseViewTestClassWithPk,
)


class TestList(BaseViewTestClass):
	_endpoint = "application-list"

	def test_success(
		self,
		admin_user_client: APIClient,
		mocker: MockerFixture,
		f_application: Application,
		f_application_group: ApplicationSecurityGroup,
		f_client: Client,
	):
		m_headers = [
			"name",
			"redirect_uris",
			"enabled",
		]
		m_list_apps = mocker.patch.object(
			ApplicationViewSet,
			"list_applications",
			return_value={
				"headers": m_headers,
				"applications": [ApplicationSerializer(f_application).data],
			},
		)

		response: Response = admin_user_client.get(self.endpoint)

		m_list_apps.assert_called_once()
		assert response.status_code == status.HTTP_200_OK
		data: dict = response.data
		assert len(data.get("applications")) == 1
		assert set(data.get("headers")) == set(m_headers)


class TestInsert(BaseViewTestClass):
	_endpoint = "application-list"

	def test_success(self, admin_user_client: APIClient):
		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				"name": "Test Application Create",
				"enabled": True,
				"client_id": "test-client-id",
				"client_secret": "test-client-secret",
				"redirect_uris": "https://example.com/callback",
				"scopes": "openid profile",
				"require_consent": False,
				"reuse_consent": False,
				"response_types": {
					"code": True,
					"id_token": False,
					"id_token token": False,
					"code token": False,
					"code id_token": False,
					"code id_token token": False,
				},
			},
			format="json",
		)
		created_app = Application.objects.get(name="Test Application Create")
		created_client = Client.objects.get(client_id=created_app.client_id)

		assert response.status_code == status.HTTP_200_OK
		assert created_app.client_id != "test-client-id"
		assert created_app.client_secret != "test-client-secret"
		assert created_client.client_secret == created_app.client_secret


class TestDelete(BaseViewTestClassWithPk):
	_endpoint = "application-detail"

	def test_success(
		self,
		admin_user_client: APIClient,
		f_application: Application,
		f_application_group: ApplicationSecurityGroup,
		f_client: Client,
	):
		m_app_id = Application.objects.first().id
		self._pk = m_app_id

		response: Response = admin_user_client.delete(self.endpoint)

		assert response.status_code == status.HTTP_200_OK
		assert Application.objects.count() == 0
		assert ApplicationSecurityGroup.objects.count() == 0
		assert Client.objects.count() == 0


class TestFetch(BaseViewTestClassWithPk):
	_endpoint = "application-detail"

	def test_success(
		self,
		admin_user_client: APIClient,
		f_application: Application,
		f_application_group: ApplicationSecurityGroup,
		f_client: Client,
	):
		m_app_id = Application.objects.first().id
		self._pk = m_app_id

		response: Response = admin_user_client.get(self.endpoint)

		assert response.status_code == status.HTTP_200_OK
		data = response.data.get("data")
		response_types = response.data.get("response_types")
		assert data["id"] == m_app_id
		for key in (
			"name",
			"enabled",
			"client_id",
			"client_secret",
			"redirect_uris",
		):
			assert data[key] == getattr(f_application, key)
		assert data["scopes"] == f_application.scopes.split()
		assert data["client_id"] == f_client.client_id
		assert set(response_types) == {
			"code",
			"id_token",
			"id_token token",
			"code token",
			"code id_token",
			"code id_token token",
		}


class TestUpdate(BaseViewTestClassWithPk):
	_endpoint = "application-detail"

	def test_success(
		self,
		admin_user_client: APIClient,
		f_application: Application,
		f_application_group: ApplicationSecurityGroup,
		f_client: Client,
	):
		self._pk = f_application.id
		admin_user_client.put(
			self.endpoint,
			data={"name": "New Name"},
			format="json",
		)
		f_application.refresh_from_db()
		assert f_application.name == "New Name"
