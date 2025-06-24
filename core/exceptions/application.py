from core.exceptions.base import CoreException
from rest_framework import status

# Application Custom Exceptions


class ApplicationExists(CoreException):
	status_code = status.HTTP_409_CONFLICT
	default_detail = "The SSO Application already exists."
	default_code = "application_exists"


class ApplicationDoesNotExist(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "The SSO Application does not exist."
	default_code = "application_does_not_exist"


class ApplicationCouldNotBeFetched(CoreException):
	status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
	default_detail = "SSO Application could not be fetched."
	default_code = "application_could_not_be_fetched"


class ApplicationFieldDoesNotExist(CoreException):
	status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
	default_detail = "A requested field does not exist."
	default_code = "application_field_does_not_exist"


class ApplicationOidcClientDoesNotExist(CoreException):
	status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
	default_detail = "OIDC Client for Application does not exist."
	default_code = "application_oidc_client_does_not_exist"
