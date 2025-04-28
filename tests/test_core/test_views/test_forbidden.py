from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework import status


def test_normal_user_forbidden(g_authenticated_endpoints, normal_user_client: APIClient):
	url, method = g_authenticated_endpoints
	method = getattr(normal_user_client, method)
	response: Response = method(url)
	assert response.status_code == status.HTTP_403_FORBIDDEN
