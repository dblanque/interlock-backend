import pytest
from pytest_mock import MockType
from core.models.ldap_tree import LDAPTree
from core.models.ldap_object import LDAPObject
from core.config.runtime import RuntimeSettings


# Create a spy wrapper to track calls AND execute original
def init_spy(self, *args, **kwargs):
	"""Wrapper that calls original __init__ and records the call"""
	LDAPObject.__init__(self, *args, **kwargs)


class TestLDAPTree:
	def test_init_sets_default_values(self, mocker, f_connection):
		"""Test that LDAPTree initializes with correct default values"""
		# Instantiate
		tree = LDAPTree(connection=f_connection)

		# Verify defaults
		assert tree.children_object_type == "array"
		assert tree.subobject_id == 0
		assert tree.recursive is False
		assert tree.test_fetch is False
		assert hasattr(tree, "ldap_filter")

	def test_init_with_custom_kwargs(self, mocker, f_connection):
		"""Test initialization with custom parameters"""
		custom_kwargs = {
			"recursive": True,
			"test_fetch": True,
			"children_object_type": "dict",
			"custom_attr": "value",
		}

		tree = LDAPTree(connection=f_connection, **custom_kwargs)

		# Verify custom values
		assert tree.recursive is True
		assert tree.test_fetch is True
		assert tree.children_object_type == "dict"
		assert tree.custom_attr == "value"

	def test_fetch_tree_basic(self, mocker, f_connection):
		"""Test basic tree fetching functionality"""
		# Setup
		mock_entry = mocker.MagicMock()
		mock_entry.entry_dn = "CN=Test,DC=example,DC=com"
		mock_entry.objectCategory = (
			"CN=Organizational-Unit,CN=Schema,CN=Configuration,DC=example,DC=com"
		)
		mock_entry.objectClass = ["top", "organizationalUnit"]

		f_connection.entries = [mock_entry]

		# Test
		tree = LDAPTree(connection=f_connection)

		# Verify
		f_connection.search.assert_called_once_with(
			search_base=RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
			search_filter=tree.ldap_filter,
			search_scope="LEVEL",
			attributes=tree.ldap_attrs,
		)

		assert len(tree.children) == 1
		assert tree.children[0]["name"] == "Test"
		assert tree.children[0]["type"] == "Organizational-Unit"

	def test_fetch_tree_recursive(self, mocker, f_connection):
		"""Test recursive tree fetching"""
		# Setup
		mocker.patch.object(
			LDAPTree,
			"__get_children__",
			return_value=[{"name": "Child", "id": 1, "type": "Organizational-Unit"}],
		)

		mock_entry = mocker.MagicMock()
		mock_entry.entry_dn = "CN=Parent,DC=example,DC=com"
		mock_entry.objectCategory = (
			"CN=Organizational-Unit,CN=Schema,CN=Configuration,DC=example,DC=com"
		)
		mock_entry.objectClass = ["top", "organizationalUnit"]
		f_connection.entries = [mock_entry]

		# Test recursive
		tree = LDAPTree(connection=f_connection, recursive=True)

		# Verify
		assert len(tree.children) == 1
		assert "children" in tree.children[0]
		assert tree.children[0]["children"][0]["name"] == "Child"
		LDAPTree.__get_children__.assert_called_once_with(mock_entry.entry_dn)

	def test_fetch_tree_dict_mode(self, mocker, f_connection):
		"""Test tree fetching in dictionary mode"""
		mock_entry = mocker.MagicMock()
		mock_entry.entry_dn = "CN=Test,DC=example,DC=com"
		mock_entry.objectCategory = (
			"CN=Organizational-Unit,CN=Schema,CN=Configuration,DC=example,DC=com"
		)
		mock_entry.objectClass = ["top", "organizationalUnit"]
		f_connection.entries = [mock_entry]

		tree = LDAPTree(connection=f_connection, children_object_type="dict")

		assert isinstance(tree.children, dict)

	def test_get_children_raises_no_distinguished_name(self, mocker, f_connection):
		tree = LDAPTree(connection=f_connection)
		with pytest.raises(ValueError):
			tree.__get_children__(distinguished_name=None)

	def test_get_children_basic(self, mocker, f_connection):
		"""Test __get_children__ method"""
		# Setup mock paged search
		mock_search = [
			{
				"dn": "CN=Child,OU=Parent,DC=example,DC=com",
				"attributes": {
					"objectClass": ["top", "organizationalUnit"],
					"objectCategory": "CN=Organizational-Unit,CN=Schema,CN=Configuration,DC=example,DC=com",
					"cn": ["Child"],
				},
			}
		]
		f_connection.extend.standard.paged_search.return_value = mock_search

		tree = LDAPTree(connection=f_connection)
		result = tree.__get_children__("OU=Parent,DC=example,DC=com")

		# Verify
		f_connection.extend.standard.paged_search.assert_called_once_with(
			search_base="OU=Parent,DC=example,DC=com",
			search_filter=tree.ldap_filter,
			search_scope="LEVEL",
			attributes=tree.ldap_attrs,
		)

		assert len(result) == 1
		assert result[0]["name"] == "Child"

	def test_get_children_with_user(self, mocker, f_connection):
		"""Test __get_children__ with user objects"""
		mock_search = [
			{
				"dn": "CN=User1,OU=Users,DC=example,DC=com",
				"attributes": {
					"objectClass": ["top", "person", "organizationalPerson", "user"],
					"objectCategory": "CN=Person,CN=Schema,CN=Configuration,DC=example,DC=com",
					"cn": ["User1"],
					"sAMAccountName": ["user1"],
				},
			}
		]
		f_connection.extend.standard.paged_search.return_value = mock_search

		tree = LDAPTree(connection=f_connection)
		tree.username_identifier = "sAMAccountName"
		result = tree.__get_children__("OU=Users,DC=example,DC=com")

		assert len(result) == 1
		assert result[0]["username"] == "user1"

	def test_get_tree_count(self, mocker, f_connection):
		"""Test tree counting functionality"""
		# Setup mock tree structure
		tree = LDAPTree(connection=f_connection)
		tree.children = [
			{
				"id": 1,
				"name": "Parent",
				"children": [
					{"id": 2, "name": "Child1"},
					{"id": 3, "name": "Child2", "children": [{"id": 4, "name": "Grandchild"}]},
				],
			}
		]

		# Test counting
		assert tree.__get_tree_count__() == 4
		assert tree.__get_child_count__(tree.children[0]["children"]) == 3

	def test_builtin_object_detection(self, mocker, f_connection):
		"""Test builtin object detection"""
		# Setup builtin object
		mock_entry = mocker.MagicMock()
		mock_entry.entry_dn = "CN=Builtin,DC=example,DC=com"
		mock_entry.objectCategory = (
			"CN=Organizational-Unit,CN=Schema,CN=Configuration,DC=example,DC=com"
		)
		mock_entry.objectClass = ["top", "builtinDomain"]
		f_connection.entries = [mock_entry]

		tree = LDAPTree(connection=f_connection)

		assert tree.children[0]["builtin"] is True

	def test_sid_handling(self, mocker, f_connection):
		"""Test SID processing in child objects"""
		mock_sid_value = "S-1-5-21-123456789-1234567890-123456789-500"
		mock_sid = mocker.MagicMock()
		mock_sid.__str__.return_value = mock_sid_value
		mocker.patch("core.models.ldap_tree.SID", return_value=mock_sid)

		mock_search = [
			{
				"dn": "CN=AdminGroup,OU=Groups,DC=example,DC=com",
				"attributes": {
					"objectClass": ["top", "group"],
					"objectCategory": "CN=Group,CN=Schema,CN=Configuration,DC=example,DC=com",
					"cn": ["AdminGroup"],
					"objectSid": [b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00"],
				},
			}
		]
		f_connection.extend.standard.paged_search.return_value = mock_search

		tree = LDAPTree(connection=f_connection)
		result = tree.__get_children__("OU=Groups,DC=example,DC=com")

		assert result[0]["objectSid"] == mock_sid_value
		assert result[0]["objectRid"] == "500"
