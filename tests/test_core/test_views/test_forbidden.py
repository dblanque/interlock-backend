from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework import status


def test_normal_user_forbidden(
	g_admin_endpoints: tuple[str, str], normal_user_client: APIClient
):
	url, method = g_admin_endpoints
	method = getattr(normal_user_client, method.lower())
	response: Response = method(url.format(pk=0))
	assert response.status_code == status.HTTP_403_FORBIDDEN
