from pytest import fixture

@fixture(autouse=True)
def mock_runtime_settings(mocker):
    return mocker.patch("interlock_backend.ldap.adsi.RuntimeSettings")
