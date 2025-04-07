import pytest
from core.models.application import Application
from core.views.mixins.application import ApplicationViewMixin
from oidc_provider.models import Client, ResponseType
from core.exceptions import (
	base as exc_base,
	application as exc_app,
)
from django.db import transaction

@pytest.fixture
def f_response_map() -> dict:
	return {
		'code': 1,
		'id_token': 2,
		'id_token token': 3,
		'code id_token': 5,
		'code id_token token': 6,
		'code token': 4,
	}

@pytest.fixture(autouse=True)
def clean_up():
	yield
	Application.objects.all().delete()
	Client.objects.all().delete()

@pytest.fixture
def f_pre_application_client() -> tuple[Application, Client]:
	with transaction.atomic():
		application = Application.objects.create(
			name="Mock Application",
			redirect_uris="https://subdomain.example.com",
		)
		client = Client.objects.create(
			name=application.name,
			client_id=application.client_id,
			client_secret=application.client_secret,
			redirect_uris=application.redirect_uris.split(","),
			scope=application.scopes.split(),
		)
	return application, client

@pytest.fixture
def f_pre_application(f_pre_application_client) -> Application:
	return f_pre_application_client[0]

@pytest.fixture
def f_pre_client(f_pre_application_client) -> Client:
	return f_pre_application_client[1]

@pytest.mark.django_db
class TestApplicationMixin:
	def test_get_response_type_id_map(self, f_response_map):
		assert ApplicationViewMixin.get_response_type_id_map() == f_response_map

	def test_get_response_type_codes(self, f_response_map):
		assert (
			set(ApplicationViewMixin.get_response_type_codes()) 
			==
			set(f_response_map.keys())
		)

	def test_set_client_response_types(self, mocker, f_response_map):
		test_params = {
			"code": True,
			"id_token": False,
			"bad_key": True,
		}
		m_client = mocker.MagicMock(spec=Client)
		m_logger = mocker.patch("core.views.mixins.application.logger")
		ApplicationViewMixin().set_client_response_types(
			new_response_types=test_params,
			client=m_client
		)
		m_client.response_types.add.assert_called_once_with(f_response_map["code"])
		m_client.response_types.remove.assert_called_once_with(f_response_map["id_token"])
		m_logger.warning.assert_called_once()

	def test_get_application_data_raises_not_exists(self):
		with pytest.raises(exc_app.ApplicationDoesNotExist):
			ApplicationViewMixin().get_application_data(application_id=0)

	def test_get_application_data(self, f_pre_application, f_pre_client):
		assert ApplicationViewMixin().get_application_data(
			application_id=f_pre_application.id
		) == (f_pre_application, f_pre_client,)

	def test_get_application_data_no_client_raises(self, f_pre_application: Application, f_pre_client: Client):
		f_pre_client.delete()
		with pytest.raises(exc_app.ApplicationOidcClientDoesNotExist):
			ApplicationViewMixin().get_application_data(
				application_id=f_pre_application.id
			)

	@pytest.mark.parametrize(
		"test_scopes",
		(
			"scope1 scope2",
			["scope1", "scope2"]
		),
		ids=[
			"Scopes as comma separated string",
			"Scopes as list"
		],
	)
	def test_insert_clean_data(self, test_scopes):
		m_excluded_fields = {
			"client_id": "some_id",
			"client_secret": "some_secret",
			"enabled": True,
		}
		m_extra_fields = {
			"require_consent": True,
			"reuse_consent": False,
			"response_types": { "id_token": True },
		}
		m_values = {
			"name":"Mock Application",
			"redirect_uris":"https://subdomain.example.com",
			"scopes": test_scopes,
		}
		application_values = {
			**m_values,
			**m_extra_fields,
			**m_excluded_fields,
		}
		serializer, extra_fields = ApplicationViewMixin().insert_clean_data(data=application_values)
		expected = m_values.copy()
		expected["scopes"] = "scope1 scope2"
		assert extra_fields == m_extra_fields
		assert serializer.is_valid()
		assert serializer.data == expected | {
			"deleted_at": None,
			"notes": None,
		}

	def test_insert_clean_data_raises(self):
		m_values = {
			"name": False,
			"redirect_uris":"https://subdomain.example.com",
			"scopes":"scope1 scope2",
		}
		with pytest.raises(exc_base.BadRequest):
			ApplicationViewMixin().insert_clean_data(data=m_values)

	def test_insert_application_raises_exists(self, f_pre_application: Application):
		mixin = ApplicationViewMixin()
		m_values = {
			"name":f_pre_application.name,
			"redirect_uris":"https://subdomain.example.com",
			"scopes": "scope1 scope2"
		}
		serializer, extra_fields = mixin.insert_clean_data(data=m_values)
		with pytest.raises(exc_app.ApplicationExists):
			mixin.insert_application(serializer=serializer, extra_fields=extra_fields)

	def test_insert_application(self):
		m_excluded_fields = {
			"client_id": "some_id",
			"client_secret": "some_secret",
			"enabled": True,
		}
		m_extra_fields = {
			"require_consent": True,
			"reuse_consent": False,
			"response_types": { "id_token": True },
		}
		m_values = {
			"name":"Mock Application",
			"redirect_uris":"https://subdomain.example.com",
			"scopes": "scope1 scope2",
		}
		application_values = {
			**m_values,
			**m_extra_fields,
			**m_excluded_fields,
		}
		mixin = ApplicationViewMixin()
		serializer, extra_fields = mixin.insert_clean_data(data=application_values)
		result = mixin.insert_application(serializer=serializer, extra_fields=extra_fields)
		assert result.name == "Mock Application"
		assert Application.objects.count() == 1
		assert Client.objects.count() == 1

	def test_list_applications(self, f_pre_application, f_pre_client):
		result = ApplicationViewMixin().list_applications()
		assert isinstance(result, dict)
		assert isinstance(result["headers"], list)
		assert result["headers"].sort() == list(
			(
				"id",
				"name",
				"redirect_uris",
				"enabled",
			)
		).sort()
		assert len(result["applications"]) == 1
