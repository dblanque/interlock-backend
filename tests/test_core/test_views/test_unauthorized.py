from rest_framework.test import APIClient
from rest_framework import status
from .endpoint_utils import endpoint_test_fn
from pytest_mock import MockerFixture

def test_unauthenticated_unauthorized(
	mocker: MockerFixture,
	g_authenticated_endpoints: tuple[str, str],
	api_client: APIClient,
):
	url, method = g_authenticated_endpoints
	endpoint_test_fn(
		mocker=mocker,
		api_client=api_client,
		url=url,
		method=method,
		expected_code=status.HTTP_401_UNAUTHORIZED,
	)
