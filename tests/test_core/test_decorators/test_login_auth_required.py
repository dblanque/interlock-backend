import pytest
from core.decorators.login import auth_required  # Replace `your_module` with the actual module name
from core.models.user import User
from rest_framework.request import Request
from core.exceptions.base import PermissionDenied


@pytest.fixture
def m_request(mocker):
	request = mocker.Mock(spec=Request)
	request.user = mocker.Mock(spec=User)
	return request


@pytest.mark.parametrize(
	"is_factory, is_authenticated, is_anonymous, is_deleted, expected_result",
	[
		# Test cases for auth_required
		(True, True, False, False, "response"),  # Authenticated, not anonymous, not deleted
		(False, True, False, False, "response"),  # Same as above, but using decorator as a factory
		(True, False, True, False, "forbidden"),  # Not authenticated, anonymous
		(True, True, False, True, PermissionDenied),  # Authenticated but deleted
	],
)
def test_auth_required(
	is_factory, is_authenticated, is_anonymous, is_deleted, expected_result, m_request, mocker
):
	m_request.user.is_authenticated = is_authenticated
	m_request.user.is_anonymous = is_anonymous
	m_request.user.deleted = is_deleted

	m_view_func = mocker.Mock(return_value="response")
	mocker.patch("core.decorators.login.RemoveTokenResponse", return_value="forbidden")

	if is_factory:
		decorated_func = auth_required(m_view_func)
	else:
		decorated_func = auth_required()(m_view_func)

	if expected_result == PermissionDenied:
		with pytest.raises(PermissionDenied):
			decorated_func(None, m_request)
	else:
		result = decorated_func(None, m_request)
		assert result == expected_result

	if is_authenticated and not is_anonymous and not is_deleted:
		m_view_func.assert_called_once_with(None, m_request)
	else:
		m_view_func.assert_not_called()
