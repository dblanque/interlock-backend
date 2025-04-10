import pytest
from core.views.mixins.ldap.group import GroupViewMixin
from unittest.mock import MagicMock

@pytest.fixture
def f_group_mixin():
	mixin = GroupViewMixin()
	mixin.ldap_connection = MagicMock()
	mixin.request = MagicMock()
	mixin.request.user.id = 1
	return mixin

@pytest.fixture
def f_mock_group_entry():
	mock = MagicMock()
	mock.entry_dn = "CN=testgroup,OU=Groups,DC=domain,DC=com"
	mock.cn = "testgroup"
	return mock

class TestGroupViewMixin:
	def test_list_groups(self, f_group_mixin: GroupViewMixin, f_mock_group_entry):
		f_group_mixin.ldap_connection.entries = [f_mock_group_entry]
		f_group_mixin.ldap_filter_attr = ["cn", "member"]
		
		result, headers = f_group_mixin.list_groups()
		assert len(result) == 1
		assert "hasMembers" in headers

	@pytest.mark.django_db
	def test_create_group_success(self, f_group_mixin: GroupViewMixin):
		group_data = {
			"cn": "testgroup",
			"groupType": 0,
			"groupScope": 0,
			"path": "OU=Groups,DC=domain,DC=com"
		}
		
		result = f_group_mixin.create_group(group_data)
		assert result == f_group_mixin.ldap_connection
		f_group_mixin.ldap_connection.add.assert_called_once()
