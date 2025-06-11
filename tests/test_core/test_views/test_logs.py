########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType

################################################################################
from tests.test_core.test_views.conftest import BaseViewTestClass
from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework import status
from core.models.user import User
from core.models.log import Log
from core.models.choices.log import (
	LOG_ACTION_READ,
	LOG_CLASS_USER,
	LOG_CLASS_GROUP,
	LOG_CLASS_DNSR,
	LOG_TARGET_ALL,
)


@pytest.fixture
def f_log_dataset(admin_user: User):
	logs = []
	for instance in (
		Log(
			user=admin_user,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_USER,
			log_target=LOG_TARGET_ALL,
		),
		Log(
			user=admin_user,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_GROUP,
			log_target=LOG_TARGET_ALL,
		),
		Log(
			user=admin_user,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_DNSR,
			log_target=LOG_TARGET_ALL,
		),
	):
		instance.save()
		logs.append(instance)
	return logs


class TestList(BaseViewTestClass):
	_endpoint = "logs-list"

	# Test Mocked
	def test_success_mocked(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
	):
		m_log_objects_all = mocker.patch(
			"core.views.logs.Log.objects.all", return_value=[]
		)
		response: Response = admin_user_client.get(self.endpoint)
		m_log_objects_all.assert_called_once()
		assert response.status_code == status.HTTP_200_OK
		assert set(response.data.get("headers")) == {
			"id",
			"date",
			"user",
			"actionType",
			"objectClass",
			"affectedObject",
			"extraMessage",
		}

	def test_success_with_logs(
		self,
		admin_user_client: APIClient,
		f_log_dataset: list[Log],
	):
		expected_headers = {
			"id",
			"date",
			"user",
			"actionType",
			"objectClass",
			"affectedObject",
			"extraMessage",
		}

		# Execution
		response: Response = admin_user_client.get(self.endpoint)
		response_logs: list[dict] = response.data.get("logs")
		assert response.status_code == status.HTTP_200_OK

		# Assertions
		assert isinstance(response_logs, list)
		assert len(response_logs) == len(f_log_dataset)
		assert all(l["actionType"] == LOG_ACTION_READ for l in response_logs)
		assert response_logs[0]["objectClass"] == LOG_CLASS_USER
		assert response_logs[0]["date"] == f_log_dataset[0].logged_at.strftime(
			"%Y-%m-%dT%H:%M:%S.%f%z"
		)
		assert response_logs[1]["objectClass"] == LOG_CLASS_GROUP
		assert response_logs[2]["objectClass"] == LOG_CLASS_DNSR
		assert all(set(l.keys()) == expected_headers for l in response_logs)
		assert set(response.data.get("headers")) == expected_headers

	def test_success_no_logs(
		self,
		admin_user_client: APIClient,
	):
		response: Response = admin_user_client.get(self.endpoint)
		assert response.status_code == status.HTTP_200_OK
		assert not Log.objects.exists()
		assert not len(response.data.get("logs"))
		assert isinstance(response.data.get("logs"), list)
		assert set(response.data.get("headers")) == {
			"id",
			"date",
			"user",
			"actionType",
			"objectClass",
			"affectedObject",
			"extraMessage",
		}


class TestReset(BaseViewTestClass):
	_endpoint = "logs-reset"

	def test_success(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
		f_log_dataset: list[Log],
	):
		assert Log.objects.all().exists()
		response: Response = admin_user_client.get(self.endpoint)
		assert response.status_code == status.HTTP_200_OK
		assert not Log.objects.all().exists()


class TestTruncate(BaseViewTestClass):
	_endpoint = "logs-truncate"

	def test_success(
		self,
		admin_user_client: APIClient,
		f_log_dataset: list[Log],
	):
		assert Log.objects.all().count() == len(f_log_dataset)
		response: Response = admin_user_client.post(
			self.endpoint,
			data={
				"min": f_log_dataset[1].id,
				"max": f_log_dataset[2].id,
			},
			format="json",
		)
		assert response.status_code == status.HTTP_200_OK
		assert Log.objects.filter(id=f_log_dataset[0].id).exists()
		assert not Log.objects.filter(id=f_log_dataset[1].id).exists()
		assert not Log.objects.filter(id=f_log_dataset[2].id).exists()

	@pytest.mark.parametrize(
		"delete_key",
		(
			"min",
			"max",
		),
	)
	def test_missing_field(
		self,
		admin_user_client: APIClient,
		delete_key: str,
	):
		m_data = {
			"min": 2,
			"max": 3,
		}
		del m_data[delete_key]

		response: Response = admin_user_client.post(
			self.endpoint,
			data=m_data,
			format="json",
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST

	@pytest.mark.parametrize(
		"bad_key",
		(
			"min",
			"max",
		),
	)
	def test_not_int_raises(
		self,
		admin_user_client: APIClient,
		bad_key: str,
	):
		m_data = {
			"min": 2,
			"max": 3,
		}
		m_data[bad_key] = "abcd"

		response: Response = admin_user_client.post(
			self.endpoint,
			data=m_data,
			format="json",
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert "must be of type int" in response.data.get("detail")
