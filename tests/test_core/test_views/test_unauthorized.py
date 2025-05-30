from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework import status


def test_unauthenticated_unauthorized(
	g_authenticated_endpoints: tuple[str, str], api_client: APIClient
):
	url, method = g_authenticated_endpoints
	method = getattr(api_client, method.lower())
	response: Response = method(url)
	assert response.status_code == status.HTTP_401_UNAUTHORIZED
