########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType

################################################################################
from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework import status
from core.models.user import User
from core.models.application import Application, ApplicationSecurityGroup
from oidc_provider.models import Client
from core.constants.attrs import (
	LOCAL_ATTR_ID,
	LOCAL_ATTR_NAME,
	LOCAL_ATTR_USERNAME,
)


class TestCreateInfo:
	endpoint = "/api/application/group/create_info/"

	def test_success_asg_exists(
		self,
		admin_user_client: APIClient,
		f_application: Application,
		f_application_group: ApplicationSecurityGroup,
		f_client: Client,
	):
		response: Response = admin_user_client.get(self.endpoint)
		assert response.status_code == status.HTTP_200_OK
		data: dict = response.data.get("data")
		assert "applications" in data
		assert "users" in data
		assert len(data["applications"]) == 0

	def test_success_asg_not_exists(
		self,
		admin_user_client: APIClient,
		f_application: Application,
		f_application_group: ApplicationSecurityGroup,
		f_client: Client,
	):
		f_application_group.delete_permanently()
		response: Response = admin_user_client.get(self.endpoint)
		assert response.status_code == status.HTTP_200_OK
		data: dict = response.data.get("data")
		assert "applications" in data
		assert "users" in data
		assert len(data["applications"]) == 1
		assert data["applications"][0] == {
			LOCAL_ATTR_ID: f_application.id,
			LOCAL_ATTR_NAME: f_application.name,
		}
		usernames = [u.get(LOCAL_ATTR_USERNAME) for u in data["users"]]
		for username in ("testuser", "testuserlocal"):
			assert username in usernames


class TestInsert:
	endpoint = "/api/application/group/insert/"

	def test_exists_raises(
		self,
		admin_user_client: APIClient,
		f_application: Application,
		f_application_group: ApplicationSecurityGroup,
		f_client: Client,
	):
		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				"application": f_application.id,
				"users": [],
				"ldap_objects": ["some_group_dn"],
				"enabled": True,
			},
			format="json",
		)
		assert response.status_code == status.HTTP_409_CONFLICT

	def test_success(
		self,
		admin_user_client: APIClient,
		f_application: Application,
		f_application_group: ApplicationSecurityGroup,
		f_client: Client,
	):
		f_application_group.delete_permanently()
		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				"application": f_application.id,
				"users": [],
				"ldap_objects": ["some_group_dn"],
				"enabled": True,
			},
			format="json",
		)
		assert response.status_code == status.HTTP_200_OK
		assert (
			ApplicationSecurityGroup.objects.filter(
				application=f_application.id
			).count()
			== 1
		)


class TestList:
	endpoint = "/api/application/group/"

	def test_success(
		self,
		admin_user_client: APIClient,
		f_application: Application,
		f_application_group: ApplicationSecurityGroup,
		f_client: Client,
	):
		response: Response = admin_user_client.get(self.endpoint)
		data: dict = response.data
		assert "application_groups" in data
		assert "headers" in data
		assert set(data["headers"]) == {
			"application",
			"enabled",
		}
		assert (
			data["application_groups"][0][LOCAL_ATTR_ID]
			== f_application_group.id
		)


class TestRetrieve:
	endpoint = "/api/application/group/{pk}/"

	def test_success(
		self,
		admin_user_client: APIClient,
		f_application: Application,
		f_application_group: ApplicationSecurityGroup,
		f_client: Client,
	):
		response: Response = admin_user_client.get(
			self.endpoint.format(pk=f_application_group.id)
		)
		data = response.data.get("data")
		assert data[LOCAL_ATTR_ID] == f_application_group.id
		assert data["enabled"]
		assert data["application"][LOCAL_ATTR_ID] == f_application.id


class TestUpdate:
	endpoint = "/api/application/group/{pk}/"

	def test_success(
		self,
		admin_user_client: APIClient,
		f_user_local: User,
		f_application: Application,
		f_application_group: ApplicationSecurityGroup,
		f_client: Client,
	):
		assert f_application_group.users.count() == 2
		response: Response = admin_user_client.put(
			self.endpoint.format(pk=f_application_group.id),
			data={
				"application": f_application.id,
				"users": [f_user_local.id],
				"enabled": False,
			},
			format="json",
		)
		f_application_group.refresh_from_db()

		assert response.status_code == status.HTTP_200_OK
		assert not f_application_group.enabled
		assert f_application_group.users.count() == 1

	def test_non_matching_id_raises(
		self,
		admin_user_client: APIClient,
		f_application: Application,
		f_application_group: ApplicationSecurityGroup,
		f_client: Client,
	):
		response: Response = admin_user_client.put(
			self.endpoint.format(pk=f_application_group.id),
			data={
				"application": f_application.id + 1,
				"enabled": False,
			},
			format="json",
		)

		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert "does not match" in response.data.get("detail")


class TestChangeStatus:
	endpoint = "/api/application/group/{pk}/change_status/"

	@pytest.mark.parametrize(
		"was_enabled, data_enabled, expects_enabled",
		(
			(
				False,
				True,
				True,
			),
			(
				True,
				False,
				False,
			),
			(
				True,
				True,
				True,
			),
			(
				False,
				False,
				False,
			),
		),
		ids=[
			"Enable disabled ASG",
			"Disable enabled ASG",
			"Enable enabled ASG",
			"Disable disabled ASG",
		],
	)
	def test_success(
		self,
		was_enabled: bool,
		data_enabled: bool,
		expects_enabled: bool,
		admin_user_client: APIClient,
		f_application: Application,
		f_application_group: ApplicationSecurityGroup,
		f_client: Client,
	):
		f_application_group.enabled = was_enabled
		f_application_group.save()
		f_application_group.refresh_from_db()

		response: Response = admin_user_client.patch(
			self.endpoint.format(pk=f_application_group.id),
			data={"enabled": data_enabled},
			format="json",
		)
		assert response.status_code == status.HTTP_200_OK
		f_application_group.refresh_from_db()
		assert f_application_group.enabled == expects_enabled


class TestDelete:
	endpoint = "/api/application/group/{pk}/delete/"

	def test_success(
		self,
		admin_user_client: APIClient,
		f_application: Application,
		f_application_group: ApplicationSecurityGroup,
		f_client: Client,
	):
		response: Response = admin_user_client.delete(
			self.endpoint.format(pk=f_application_group.id),
		)
		assert response.status_code == status.HTTP_200_OK
		assert ApplicationSecurityGroup.objects.count() == 0
