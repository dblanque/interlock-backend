########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture
################################################################################
from core.models.ldap_object import LDAPObjectTypes
from tests.test_core.conftest import (
	LDAPAttributeFactoryProtocol,
	LDAPEntryFactoryProtocol,
)
from core.type_hints.connector import LDAPConnectionProtocol
from core.models.ldap_tree import LDAPTree
from core.models.ldap_object import LDAPObject
from core.config.runtime import RuntimeSettings
from core.constants.attrs import *
from ldap3 import LEVEL, Entry as LDAPEntry
from tests.test_core.conftest import RuntimeSettingsFactory
from tests.test_core.test_models.conftest import LDAPConnectionFactoryProtocol
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton

# Create a spy wrapper to track calls AND execute original
def init_spy(self, *args, **kwargs):
	"""Wrapper that calls original __init__ and records the call"""
	LDAPObject.__init__(self, *args, **kwargs)

@pytest.fixture(autouse=True)
def f_runtime_settings(g_runtime_settings: RuntimeSettingsFactory):
	return g_runtime_settings(patch_path="core.models.ldap_tree.RuntimeSettings")

@pytest.fixture
def f_tree_entry(fc_ldap_entry: LDAPEntryFactoryProtocol):
	return fc_ldap_entry(**{
		LDAP_ATTR_DN: "CN=Parent,DC=example,DC=com",
		LDAP_ATTR_OBJECT_CATEGORY: "CN=Organizational-Unit,CN=Schema,CN=Configuration,DC=example,DC=com",
		LDAP_ATTR_OBJECT_CLASS: ["top", "organizationalUnit"],
	})

class TestLDAPTree:
	def test_init_raises_no_connection(self):
		with pytest.raises(Exception, match="requires an LDAP Connection"):
			LDAPTree()

	def test_init_sets_default_values(self, mocker: MockerFixture, f_connection):
		"""Test that LDAPTree initializes with correct default values"""
		# Instantiate
		tree = LDAPTree(connection=f_connection)

		# Verify defaults
		assert tree.children_object_type == list
		assert tree.subobject_id == 0
		assert tree.recursive is False
		assert hasattr(tree, "search_filter")

	def test_init_with_custom_kwargs(self, mocker: MockerFixture, f_connection):
		"""Test initialization with custom parameters"""
		custom_kwargs = {
			"recursive": True,
			"children_object_type": dict,
			"custom_attr": "value",
		}
		m_fetch_tree = mocker.patch.object(
			LDAPTree,
			"__fetch_tree__",
			return_value=None
		)

		tree = LDAPTree(
			connection=f_connection, **custom_kwargs)

		# Verify custom values
		assert tree.recursive is True
		assert tree.children_object_type == dict
		assert tree.custom_attr == "value"
		m_fetch_tree.assert_called_once()

	def test_fetch_tree_basic(
			self,
			mocker: MockerFixture,
			f_connection: LDAPConnectionProtocol,
			f_tree_entry,
		):
		"""Test basic tree fetching functionality"""
		f_connection.entries = [f_tree_entry]

		# Test
		tree = LDAPTree(connection=f_connection)

		# Verify
		f_connection.search.assert_called_once_with(
			search_base=RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
			search_filter=tree.search_filter,
			search_scope=LEVEL,
			attributes=tree.search_attrs,
		)

		assert len(tree.children) == 1
		assert tree.children[0]["name"] == "Parent"
		assert tree.children[0]["type"] == LDAPObjectTypes.ORGANIZATIONAL_UNIT.value

	def test_fetch_tree_recursive(
		self,
		mocker: MockerFixture,
		f_connection: LDAPConnectionProtocol,
		f_tree_entry: LDAPEntry,
	):
		"""Test recursive tree fetching"""
		# Setup
		mocker.patch.object(
			LDAPTree,
			"__get_children__",
			return_value=[
				{
					LOCAL_ATTR_NAME: "Child",
					LOCAL_ATTR_ID: 1,
					LOCAL_ATTR_TYPE: LDAPObjectTypes.ORGANIZATIONAL_UNIT.value,
				}
			],
		)
		f_connection.entries = [f_tree_entry]

		# Test recursive
		tree = LDAPTree(connection=f_connection, recursive=True)

		# Verify
		assert len(tree.children) == 1
		assert "children" in tree.children[0]
		assert tree.children[0]["children"][0]["name"] == "Child"
		LDAPTree.__get_children__.assert_called_once_with(f_tree_entry.entry_dn)

	def test_fetch_tree_dict_mode(
		self,
		f_connection: LDAPConnectionProtocol,
		f_tree_entry: LDAPEntry,
	):
		"""Test tree fetching in dictionary mode"""
		f_connection.entries = [f_tree_entry]

		tree = LDAPTree(connection=f_connection, children_object_type=dict)
		assert isinstance(tree.children, dict)

	def test_get_children_raises_no_distinguished_name(self, f_connection):
		tree = LDAPTree(connection=f_connection)
		with pytest.raises(ValueError):
			tree.__get_children__(distinguished_name=None)

	def test_get_children_basic(
		self,
		mocker: MockerFixture,
		fc_connection: LDAPConnectionFactoryProtocol,
		fc_ldap_attr: LDAPAttributeFactoryProtocol,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		"""Test __get_children__ method"""
		fake_entry_attrs = (LDAP_ATTR_OBJECT_CLASS, LDAP_ATTR_OBJECT_CATEGORY, LDAP_ATTR_COMMON_NAME)
		# Setup mock search
		mock_parent = mocker.Mock(name="mock_parent", spec=LDAPEntry)
		mock_parent.entry_attributes = fake_entry_attrs
		mock_parent.entry_dn = "OU=Parent,DC=example,DC=com"
		mock_parent.objectClass = fc_ldap_attr(
			LDAP_ATTR_OBJECT_CLASS,
			["top", "organizationalUnit"]
		)
		mock_parent.objectCategory = fc_ldap_attr(
			LDAP_ATTR_OBJECT_CATEGORY,
			"CN=Organizational-Unit,CN=Schema,CN=Configuration,DC=example,DC=com"
		)
		mock_parent.cn = fc_ldap_attr(
			LDAP_ATTR_COMMON_NAME, "Parent"
		)
		mock_child = mocker.Mock(name="mock_child", spec=LDAPEntry)
		mock_child.entry_attributes = fake_entry_attrs
		mock_child.entry_dn = "CN=Child,OU=Parent,DC=example,DC=com"
		mock_child.objectClass = fc_ldap_attr(
			LDAP_ATTR_OBJECT_CLASS,
			["top", "organizationalUnit"]
		)
		mock_child.objectCategory = fc_ldap_attr(
			LDAP_ATTR_OBJECT_CATEGORY,
			"CN=Organizational-Unit,CN=Schema,CN=Configuration,DC=example,DC=com"
		)
		mock_child.cn = fc_ldap_attr(
			LDAP_ATTR_COMMON_NAME, "Child"
		)

		# Mock Connection
		f_connection = fc_connection()
		f_connection.search = mocker.Mock(
			side_effect=(
				setattr(f_connection, "entries", [mock_parent]),
				setattr(f_connection, "entries", [mock_child]),
			)
		)

		tree = LDAPTree(connection=f_connection)
		resulting_children = tree.__get_children__("OU=Parent,DC=example,DC=com")
		resulting_child = resulting_children[0]

		# Verify
		f_connection.search.assert_any_call(
			search_base=f_runtime_settings.LDAP_AUTH_SEARCH_BASE,
			search_filter=tree.search_filter,
			search_scope=LEVEL,
			attributes=tree.search_attrs,
		)
		f_connection.search.assert_any_call(
			search_base=mock_parent.entry_dn,
			search_filter=tree.search_filter,
			search_scope=LEVEL,
			attributes=tree.search_attrs,
		)

		assert len(resulting_children) == 1
		assert resulting_child[LOCAL_ATTR_NAME] == "Child"
		assert resulting_child[LOCAL_ATTR_OBJECT_CATEGORY] == 'CN=Organizational-Unit,CN=Schema,CN=Configuration,DC=example,DC=com'
		assert resulting_child[LOCAL_ATTR_TYPE] == LDAPObjectTypes.ORGANIZATIONAL_UNIT.value
		assert resulting_child[LOCAL_ATTR_OBJECT_CLASS] == ['top', 'organizationalUnit']

	def test_get_tree_count(
		self,
		mocker: MockerFixture,
		f_connection: LDAPConnectionProtocol
	):
		"""Test tree counting functionality"""
		# Setup mock tree structure
		tree = LDAPTree(connection=f_connection)
		tree.children = [
			{
				LOCAL_ATTR_ID: 1,
				LOCAL_ATTR_NAME: "Parent",
				"children": [
					{LOCAL_ATTR_ID: 2, LOCAL_ATTR_NAME: "Child1"},
					{
						LOCAL_ATTR_ID: 3,
						LOCAL_ATTR_NAME: "Child2",
						"children": [{LOCAL_ATTR_ID: 4, LOCAL_ATTR_NAME: "Grandchild"}],
					},
				],
			}
		]

		# Test counting
		assert tree.__get_tree_count__() == 4
		assert tree.__get_child_count__(tree.children[0]["children"]) == 3

	def test_builtin_object_detection(
		self,
		f_connection: LDAPConnectionProtocol,
		fc_ldap_entry: LDAPEntryFactoryProtocol,
	):
		"""Test builtin object detection"""
		# Setup builtin object
		mock_entry = fc_ldap_entry(**{
			LDAP_ATTR_DN: "CN=Builtin,DC=example,DC=com",
			LDAP_ATTR_OBJECT_CATEGORY: "CN=Organizational-Unit,CN=Schema,CN=Configuration,DC=example,DC=com",
			LDAP_ATTR_OBJECT_CLASS: ["top", "builtinDomain"]
		})
		f_connection.entries = [mock_entry]

		tree = LDAPTree(connection=f_connection)
		assert tree.children[0][LOCAL_ATTR_BUILT_IN] is True
