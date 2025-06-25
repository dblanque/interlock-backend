from rest_framework.test import APIClient
from pytest_mock import MockerFixture
from rest_framework import status
from .endpoint_utils import endpoint_test_fn

def test_disabled_user_unauthorized(
	mocker: MockerFixture,
	g_all_endpoints: tuple[str, str],
	disabled_user_client: APIClient,
):
	url, method = g_all_endpoints
	endpoint_test_fn(
		mocker=mocker,
		api_client=disabled_user_client,
		url=url,
		method=method,
		expected_code=status.HTTP_401_UNAUTHORIZED,
	)
