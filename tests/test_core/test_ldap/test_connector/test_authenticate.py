import pytest
from interlock_backend.test_settings import DEFAULT_SUPERUSER_USERNAME

@pytest.mark.parametrize(
	"func_args, func_kwargs, expected",
	(
		# Test Cases
		(), # Local Superadmin
	)
)
def test_authenticate(func_args, func_kwargs, expected, mocker, m_runtime_settings, m_connection):
	pass

def test_authenticate_malformed_data():
	pass

def test_authenticate_fail():
	pass
