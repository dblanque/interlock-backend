from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework import status


def test_disabled_user_unauthorized(
	g_all_endpoints, disabled_user_client: APIClient
):
	url, method = g_all_endpoints
	method = getattr(disabled_user_client, method)
	response: Response = method(url)
	assert response.status_code == status.HTTP_401_UNAUTHORIZED
