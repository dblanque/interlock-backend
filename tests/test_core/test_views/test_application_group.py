########################### Standard Pytest Imports ############################
import pytest

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
from tests.test_core.test_views.conftest import (
	BaseViewTestClass,
	BaseViewTestClassWithPk,
)
from tests.test_core.conftest import ConnectorFactory, LDAPEntryFactoryProtocol
from core.constants.attrs.ldap import LDAP_ATTR_SECURITY_ID, LDAP_ATTR_DN
from core.models.ldap_ref import LdapRef

@pytest.fixture(autouse=True)
def f_ldap_connector(
	g_ldap_connector: ConnectorFactory,
	f_ldap_ref: LdapRef,
	fc_ldap_entry: LDAPEntryFactoryProtocol,
):
	connector = g_ldap_connector(
		patch_path=(
			"core.serializers.application_group.LDAPConnector",
			"core.models.application.LDAPConnector",
		)
	)
	connector.connection.entries = [ # type: ignore
		fc_ldap_entry(
			spec=False,
			**{
				LDAP_ATTR_DN: f_ldap_ref.distinguished_name,
				LDAP_ATTR_SECURITY_ID: f_ldap_ref.object_security_id_bytes
			}
		)
	]
	return connector

class TestCreateInfo(BaseViewTestClass):
	_endpoint = "application/group-create-info"

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


class TestInsert(BaseViewTestClass):
	_endpoint = "application/group-list"

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
				"ldap_objects": [],
				"enabled": True,
			},
			format="json",
		) # type: ignore
		assert response.status_code == status.HTTP_409_CONFLICT

	def test_success(
		self,
		admin_user_client: APIClient,
		f_application: Application,
		f_application_group: ApplicationSecurityGroup,
		f_client: Client,
		f_ldap_ref: LdapRef,
		g_interlock_ldap_enabled,
	):
		f_application_group.delete_permanently()
		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				"application": f_application.id,
				"users": [],
				"ldap_objects": [f_ldap_ref.distinguished_name],
				"enabled": True,
			},
			format="json",
		) # type: ignore
		asg = ApplicationSecurityGroup.objects.get(
			application_id=f_application.id)
		assert response.status_code == status.HTTP_200_OK
		assert asg.ldap_objects == [f_ldap_ref.distinguished_name]
		assert (
			ApplicationSecurityGroup.objects.filter(
				application=f_application.id
			).count() == 1
		)


class TestList(BaseViewTestClass):
	_endpoint = "application/group-list"

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


class TestRetrieve(BaseViewTestClassWithPk):
	_endpoint = "application/group-detail"

	def test_success(
		self,
		admin_user_client: APIClient,
		f_application: Application,
		f_application_group: ApplicationSecurityGroup,
		f_client: Client,
	):
		self._pk = f_application_group.id
		response: Response = admin_user_client.get(self.endpoint)
		data = response.data.get("data")
		assert data[LOCAL_ATTR_ID] == f_application_group.id
		assert data["enabled"]
		assert data["application"][LOCAL_ATTR_ID] == f_application.id


class TestUpdate(BaseViewTestClassWithPk):
	_endpoint = "application/group-detail"

	def test_success(
		self,
		admin_user_client: APIClient,
		f_user_local: User,
		f_application: Application,
		f_application_group: ApplicationSecurityGroup,
		f_client: Client,
		f_ldap_ref: LdapRef,
		g_interlock_ldap_enabled
	):
		self._pk = f_application_group.id
		assert f_application_group.users.count() == 1
		response: Response = admin_user_client.put(
			self.endpoint,
			data={
				"application": f_application.id,
				"users": [f_user_local.id],
				"ldap_objects": [f_ldap_ref.distinguished_name],
				"enabled": False,
			},
			format="json",
		)
		f_application_group.refresh_from_db()

		assert response.status_code == status.HTTP_200_OK
		assert not f_application_group.enabled
		assert f_application_group.ldap_objects == [
			f_ldap_ref.distinguished_name
		]
		assert f_application_group.users.count() == 1

	def test_non_matching_id_raises(
		self,
		admin_user_client: APIClient,
		f_application: Application,
		f_application_group: ApplicationSecurityGroup,
		f_client: Client,
	):
		self._pk = f_application_group.id
		response: Response = admin_user_client.put(
			self.endpoint,
			data={
				"application": f_application.id + 1,
				"enabled": False,
			},
			format="json",
		)

		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert "does not match" in response.data.get("detail")


class TestChangeStatus(BaseViewTestClassWithPk):
	_endpoint = "application/group-change-status"

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
		self._pk = f_application_group.id
		f_application_group.enabled = was_enabled
		f_application_group.save()
		f_application_group.refresh_from_db()

		response: Response = admin_user_client.patch(
			self.endpoint,
			data={"enabled": data_enabled},
			format="json",
		)
		assert response.status_code == status.HTTP_200_OK
		f_application_group.refresh_from_db()
		assert f_application_group.enabled == expects_enabled


class TestDelete(BaseViewTestClassWithPk):
	_endpoint = "application/group-detail"

	def test_success(
		self,
		admin_user_client: APIClient,
		f_application: Application,
		f_application_group: ApplicationSecurityGroup,
		f_client: Client,
	):
		self._pk = f_application_group.id
		response: Response = admin_user_client.delete(self.endpoint)
		assert response.status_code == status.HTTP_200_OK
		assert ApplicationSecurityGroup.objects.count() == 0

	def test_raises_not_exists(self, admin_user_client: APIClient):
		self._pk = 999
		response: Response = admin_user_client.delete(self.endpoint)
		assert response.status_code == status.HTTP_404_NOT_FOUND
		assert ApplicationSecurityGroup.objects.count() == 0
