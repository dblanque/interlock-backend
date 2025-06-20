########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture, MockType

################################################################################
from core.models.ldap_object import LDAPObject
from core.models.ldap_user import LDAPUser, DEFAULT_LOCAL_ATTRS
from core.constants.attrs import *
from core.ldap.filter import LDAPFilter, LDAPFilterType
from .test_ldap_object import TestDunderValidateInit as SuperDunderValidateInit
from core.type_hints.connector import LDAPConnectionProtocol
from core.exceptions import users as exc_user, base as exc_base
from typing import Protocol
from core.ldap.adsi import (
	calc_permissions,
	LDAP_PERMS,
	LDAP_UF_ACCOUNT_DISABLE,
	LDAP_UF_NORMAL_ACCOUNT,
	LDAP_UF_DONT_EXPIRE_PASSWD,
	LDAP_UF_PASSWD_CANT_CHANGE,
)
from tests.test_core.conftest import LDAPEntryFactoryProtocol, RuntimeSettingsFactory


class InitlessLDAPUserFactory(Protocol):
	def __call__(self, **kwargs) -> LDAPUser: ...


@pytest.fixture
def f_ldap_user_no_init(mocker: MockerFixture) -> InitlessLDAPUserFactory:
	def maker(**kwargs):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_ldap_user = LDAPUser()
		for kw, val in kwargs.items():
			setattr(m_ldap_user, kw, val)
		return m_ldap_user

	return maker

class TestInit():
	def test_success(self, mocker: MockerFixture, g_runtime_settings: RuntimeSettingsFactory):
		m_runtime_settings = g_runtime_settings(
			patch_path="core.models.ldap_user.RuntimeSettings"
		)
		m_super_init = mocker.patch.object(LDAPObject, "__init__")
		m_ldap_user = LDAPUser(some_kwarg=True)
		m_super_init.assert_called_once_with(some_kwarg=True)
		assert m_ldap_user.search_attrs == {
			m_runtime_settings.LDAP_FIELD_MAP.get(attr)
			for attr in DEFAULT_LOCAL_ATTRS
			if m_runtime_settings.LDAP_FIELD_MAP.get(attr, None)
		}

class TestDunderValidateInit(SuperDunderValidateInit):
	test_cls = LDAPUser

	def test_only_with_username(self, mocker: MockerFixture):
		mocker.patch.object(self.test_cls, "__init__", return_value=None)
		m_ldap_user = self.test_cls()
		m_ldap_user.__validate_init__(**{LOCAL_ATTR_USERNAME: "testuser"})
		result_filter = LDAPFilter.from_string(m_ldap_user.search_filter)
		assert result_filter.children[1].type == LDAPFilterType.EQUALITY
		assert (
			result_filter.children[1].attribute == LDAP_ATTR_USERNAME_SAMBA_ADDS
		)
		assert result_filter.children[1].value == "testuser"


class TestParseWriteSpecialAttributes:
	def test_success(
		self,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		m_ldap_user = f_ldap_user_no_init(
			**{
				"attributes": {
					LOCAL_ATTR_USER_GROUPS: ["group_a", "group_b"],
					LOCAL_ATTR_USER_ADD_GROUPS: ["group_c_dn"],
					LOCAL_ATTR_USER_RM_GROUPS: ["group_b_dn"],
					LOCAL_ATTR_COUNTRY: "some_country",
					LOCAL_ATTR_PERMISSIONS: ["some_permissions"],
				}
			}
		)
		m_cleanup_groups_operation = mocker.patch.object(LDAPUser, "cleanup_groups_operation")
		m_parse_write_country = mocker.patch.object(
			LDAPUser, "parse_write_country"
		)
		m_parse_write_permissions = mocker.patch.object(
			LDAPUser, "parse_write_permissions"
		)
		m_ldap_user.parse_write_special_attributes()
		m_cleanup_groups_operation.call_count == 2
		m_cleanup_groups_operation.assert_any_call(
			group_dns=["group_c_dn"],
			operation="add",
		)
		m_cleanup_groups_operation.assert_any_call(
			group_dns=["group_b_dn"],
			operation="remove",
		)
		m_parse_write_country.assert_called_once_with("some_country")
		m_parse_write_permissions.assert_called_once_with(["some_permissions"])


class TestPostCreate:
	def test_success(
		self,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_ldap_user = f_ldap_user_no_init(
			**{
				"attributes": {
					LOCAL_ATTR_USER_ADD_GROUPS: ["mock_group_1"],
					LOCAL_ATTR_USER_RM_GROUPS: ["mock_group_2"],
				}
			}
		)
		m_perform_group_ops = mocker.patch.object(
			LDAPUser, "perform_group_operations"
		)
		m_ldap_user.post_create()
		m_perform_group_ops.assert_called_once_with(
			groups_to_add=m_ldap_user.attributes.get(
				LOCAL_ATTR_USER_ADD_GROUPS, []
			),
			groups_to_remove=m_ldap_user.attributes.get(
				LOCAL_ATTR_USER_RM_GROUPS, []
			),
		)


class TestPostUpdate:
	def test_success(
		self,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_ldap_user = f_ldap_user_no_init()
		m_post_create = mocker.patch.object(LDAPUser, "post_create")

		m_ldap_user.post_update()
		m_post_create.assert_called_once()


class TestSave:
	@pytest.mark.parametrize(
		"add_groups, rm_groups, expected_force_post_update",
		(
			([], [], False),
			([], ["mock_group"], True),
			(["mock_group"], [], True),
		),
	)
	def test_success(
		self,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
		add_groups,
		rm_groups,
		expected_force_post_update,
	):
		m_save = mocker.patch.object(LDAPObject, "save")
		m_ldap_user = f_ldap_user_no_init(
			attributes={
				LOCAL_ATTR_USER_ADD_GROUPS: add_groups,
				LOCAL_ATTR_USER_RM_GROUPS: rm_groups,
			}
		)
		m_ldap_user.save()
		m_save.assert_called_once_with(
			update_kwargs={
				"force_post_update": expected_force_post_update
			}
		)

class TestRemovePrimaryGroup:
	def test_returns_none_on_falsy_dn_list(
		self,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		m_ldap_user = f_ldap_user_no_init()
		assert m_ldap_user.remove_primary_group(group_dns=[]) is None

	def test_raises_type_error(
		self,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		m_ldap_user = f_ldap_user_no_init()
		with pytest.raises(TypeError):
			m_ldap_user.remove_primary_group(group_dns={"a":"dictionary"})

	def test_success(
		self,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
		fc_ldap_entry: LDAPEntryFactoryProtocol,
	):
		# Mock User
		m_primary_group_id = 513 # Default LDAP Group
		m_entry = fc_ldap_entry(**{
			LDAP_ATTR_PRIMARY_GROUP_ID: m_primary_group_id
		})
		m_ldap_user = f_ldap_user_no_init()
		m_ldap_user.entry = m_entry

		# Mock Groups
		m_group_1 = mocker.Mock()
		m_group_1.distinguished_name = "mock_dn_1"
		m_group_1.attributes = {
			LOCAL_ATTR_DN: m_group_1.distinguished_name,
			LOCAL_ATTR_RELATIVE_ID: 1105
		}
		m_group_2 = mocker.Mock()
		m_group_2.distinguished_name = "mock_dn_2"
		m_group_2.attributes = {
			LOCAL_ATTR_DN: m_group_2.distinguished_name,
			LOCAL_ATTR_RELATIVE_ID: m_primary_group_id
		}
		m_groups = [m_group_1, m_group_2]
		m_ldap_group_cls = mocker.patch(
			"core.models.ldap_group.LDAPGroup",
			side_effect=m_groups
		)

		# Execution
		result_dns, found = m_ldap_user.remove_primary_group(
			group_dns=[
				g.attributes[LOCAL_ATTR_DN]
				for g in m_groups
			]
		)

		# Assertions
		assert found
		assert isinstance(result_dns, set)
		assert result_dns == {m_group_1.attributes[LOCAL_ATTR_DN]}

class TestCleanupGroupsOperation:
	@pytest.mark.parametrize(
		"falsy_value",
		(
			"",
			[], # Empty List
			set(), # Empty Set
			False,
			None,
		),
	)
	def test_returns_none_on_falsy_dn_list(
		self,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
		falsy_value,
	):
		m_ldap_user = f_ldap_user_no_init()
		assert m_ldap_user.cleanup_groups_operation(
			group_dns=falsy_value,
			operation="add",
		) is None
		assert m_ldap_user.cleanup_groups_operation(
			group_dns=falsy_value,
			operation="remove",
		) is None

	def test_raises_type_error(
		self,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		m_ldap_user = f_ldap_user_no_init()
		with pytest.raises(TypeError, match="must be of types"):
			assert m_ldap_user.cleanup_groups_operation(
				group_dns={"a":"dictionary"},
				operation="add",
			)
		with pytest.raises(TypeError, match="must be of types"):
			assert m_ldap_user.cleanup_groups_operation(
				group_dns={"a":"dictionary"},
				operation="remove",
			)

	def test_raises_value_error_on_bad_operation(
		self,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		m_ldap_user = f_ldap_user_no_init()
		with pytest.raises(ValueError, match="operation must be"):
			assert m_ldap_user.cleanup_groups_operation(
				group_dns={"a":"dictionary"},
				operation="some_bad_value",
			)

	@pytest.mark.parametrize(
		"operation, check_attr, test_single_value",
		(
			("add", LOCAL_ATTR_USER_ADD_GROUPS, False),
			("add", LOCAL_ATTR_USER_ADD_GROUPS, True),
			("remove", LOCAL_ATTR_USER_RM_GROUPS, False),
			("remove", LOCAL_ATTR_USER_RM_GROUPS, True),
		),
	)
	def test_success(
		self,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
		fc_ldap_entry: LDAPEntryFactoryProtocol,
		operation: str,
		check_attr: str,
		test_single_value: bool,
	):
		m_remove_primary_group = mocker.patch.object(
			LDAPUser,
			"remove_primary_group",
			side_effect=lambda group_dns, *args, **kwargs: (group_dns, False)
		)
		m_entry = fc_ldap_entry(**{
			LDAP_ATTR_USER_GROUPS: ["existing_group"],
		})
		m_ldap_user = f_ldap_user_no_init()
		m_ldap_user.entry = m_entry
		m_ldap_user.parsed_specials = []
		m_groups_to_affect = ["existing_group", "new_group"]
		m_ldap_user.attributes = {
			LOCAL_ATTR_USER_ADD_GROUPS: m_groups_to_affect,
			LOCAL_ATTR_USER_RM_GROUPS: m_groups_to_affect,
		}

		# Execution
		target_dn_list = m_groups_to_affect.copy()
		if test_single_value:
			target_dn_list = (
				m_groups_to_affect[1]
				if operation == "add"
				else m_groups_to_affect[0]
			)
		m_ldap_user.cleanup_groups_operation(
			group_dns=target_dn_list,
			operation=operation,
		)

		# Assertions
		expected_groups = {
			m_groups_to_affect[1] # new_group
			if operation == "add"
			else m_groups_to_affect[0] # existing_group
		}
		m_remove_primary_group.assert_called_once_with(
			group_dns=expected_groups
		)
		assert m_ldap_user.attributes[check_attr] == expected_groups

class TestParseWriteCountry:
	def test_success(
		self,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_ldap_user = f_ldap_user_no_init(
			attributes={
				LOCAL_ATTR_COUNTRY: "Argentina",
			},
			parsed_specials=[],
		)

		m_ldap_user.parse_write_country(
			m_ldap_user.attributes[LOCAL_ATTR_COUNTRY]
		)
		assert set(m_ldap_user.parsed_specials) == set(
			[LOCAL_ATTR_COUNTRY, LOCAL_ATTR_COUNTRY_DCC, LOCAL_ATTR_COUNTRY_ISO]
		)
		assert m_ldap_user.attributes[LOCAL_ATTR_COUNTRY] == "Argentina"
		assert m_ldap_user.attributes[LOCAL_ATTR_COUNTRY_DCC] == 32
		assert m_ldap_user.attributes[LOCAL_ATTR_COUNTRY_ISO] == "AR"

	@pytest.mark.parametrize(
		"value",
		(
			"",
			None,
		),
	)
	def test_success_no_value(
		self,
		value,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_ldap_user = f_ldap_user_no_init(
			attributes={
				LOCAL_ATTR_COUNTRY: value,
			},
			parsed_specials=[],
		)

		m_ldap_user.parse_write_country(
			m_ldap_user.attributes[LOCAL_ATTR_COUNTRY]
		)
		assert set(m_ldap_user.parsed_specials) == set(
			[LOCAL_ATTR_COUNTRY, LOCAL_ATTR_COUNTRY_DCC, LOCAL_ATTR_COUNTRY_ISO]
		)
		assert m_ldap_user.attributes[LOCAL_ATTR_COUNTRY] == None
		assert m_ldap_user.attributes[LOCAL_ATTR_COUNTRY_DCC] == 0
		assert m_ldap_user.attributes[LOCAL_ATTR_COUNTRY_ISO] == None


class TestParseWritePermissions:
	@pytest.mark.parametrize(
		"permissions, expected",
		(
			(None, None),
			# Empty permissions returns default disabled + normal acc
			(
				[],
				LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["value"]
				+ LDAP_PERMS[LDAP_UF_ACCOUNT_DISABLE]["value"],
			),
			(
				[LDAP_UF_NORMAL_ACCOUNT],
				LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["value"],
			),
			(
				[
					LDAP_UF_NORMAL_ACCOUNT,
					LDAP_UF_ACCOUNT_DISABLE,
					LDAP_UF_DONT_EXPIRE_PASSWD,
				],
				LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["value"]
				+ LDAP_PERMS[LDAP_UF_ACCOUNT_DISABLE]["value"]
				+ LDAP_PERMS[LDAP_UF_DONT_EXPIRE_PASSWD]["value"],
			),
			(
				[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_ACCOUNT_DISABLE],
				LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["value"]
				+ LDAP_PERMS[LDAP_UF_ACCOUNT_DISABLE]["value"],
			),
		),
	)
	def test_success(
		self,
		permissions: list[str],
		expected: int,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_ldap_user = f_ldap_user_no_init(
			attributes={
				LOCAL_ATTR_PERMISSIONS: permissions,
			},
			parsed_specials=[],
		)

		m_ldap_user.parse_write_permissions(
			m_ldap_user.attributes[LOCAL_ATTR_PERMISSIONS]
		)
		if expected:
			assert set(m_ldap_user.parsed_specials) == {LOCAL_ATTR_UAC}
		else:
			assert not m_ldap_user.parsed_specials
		assert m_ldap_user.attributes.get(LOCAL_ATTR_UAC, None) == expected


class TestPerformGroupOperations:
	@pytest.mark.parametrize(
		"add_groups, rm_groups, expected_add, expected_rm",
		(
			(
				["mock_group_1"],
				["mock_group_2"],
				True,
				True,
			),
			(
				["mock_group_1"],
				[],
				True,
				False,
			),
			(
				[],
				["mock_group_2"],
				False,
				True,
			),
		),
	)
	def test_success(
		self,
		add_groups: list,
		rm_groups: list,
		expected_add: bool,
		expected_rm: bool,
		f_connection: LDAPConnectionProtocol,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_ldap_user = f_ldap_user_no_init(
			distinguished_name="mock_dn",
			attributes={
				LOCAL_ATTR_USER_ADD_GROUPS: add_groups,
				LOCAL_ATTR_USER_RM_GROUPS: rm_groups,
			},
			parsed_specials=[
				LOCAL_ATTR_USER_ADD_GROUPS,
				LOCAL_ATTR_USER_RM_GROUPS,
			],
		)
		m_ldap_user.connection = f_connection
		m_ldap_user.perform_group_operations(
			groups_to_add=add_groups,
			groups_to_remove=rm_groups,
		)

		if expected_add:
			m_add_members_to_groups: MockType = (
				f_connection.extend.microsoft.add_members_to_groups
			)
			m_add_members_to_groups.assert_called_once_with(
				"mock_dn", set(add_groups)
			)
		if expected_rm:
			m_remove_members_from_groups: MockType = (
				f_connection.extend.microsoft.remove_members_from_groups
			)
			m_remove_members_from_groups.assert_called_once_with(
				"mock_dn", set(rm_groups)
			)

	@pytest.mark.parametrize(
		"add_groups, rm_groups",
		(
			(
				["mock_group_1", "mock_group_2"],
				["mock_group_2"],
			),
			(
				["mock_group_1"],
				["mock_group_1"],
			),
			(
				["mock_group_1"],
				["mock_group_1", "mock_group_2"],
			),
		),
	)
	def test_raises_bad_group_selection(
		self,
		add_groups: list,
		rm_groups: list,
		f_connection: LDAPConnectionProtocol,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_ldap_user = f_ldap_user_no_init(
			distinguished_name="mock_dn",
			attributes={
				LOCAL_ATTR_USER_ADD_GROUPS: add_groups,
				LOCAL_ATTR_USER_RM_GROUPS: rm_groups,
			},
			parsed_specials=[
				LOCAL_ATTR_USER_ADD_GROUPS,
				LOCAL_ATTR_USER_RM_GROUPS,
			],
		)
		m_ldap_user.connection = f_connection
		with pytest.raises(exc_user.BadGroupSelection):
			m_ldap_user.perform_group_operations(
				groups_to_add=add_groups,
				groups_to_remove=rm_groups,
			)

		m_add_members_to_groups: MockType = (
			f_connection.extend.microsoft.add_members_to_groups
		)
		m_add_members_to_groups.assert_not_called()
		m_remove_members_from_groups: MockType = (
			f_connection.extend.microsoft.remove_members_from_groups
		)
		m_remove_members_from_groups.assert_not_called()
		assert m_ldap_user.parsed_specials == [
			LOCAL_ATTR_USER_ADD_GROUPS,
			LOCAL_ATTR_USER_RM_GROUPS,
		]

	@pytest.mark.parametrize(
		"add_groups, rm_groups",
		(
			(
				["mock_group_1", "mock_group_2"],
				["mock_group_2"],
			),
			(
				[],
				["mock_group_1"],
			),
		),
	)
	def test_raises_core_exc(
		self,
		add_groups: list,
		rm_groups: list,
		f_connection: LDAPConnectionProtocol,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_ldap_user = f_ldap_user_no_init(
			distinguished_name="mock_dn",
			attributes={
				LOCAL_ATTR_USER_ADD_GROUPS: add_groups,
				LOCAL_ATTR_USER_RM_GROUPS: rm_groups,
			},
			parsed_specials=[],
		)
		m_ldap_user.connection = f_connection
		with pytest.raises(exc_base.CoreException):
			m_ldap_user.perform_group_operations(
				groups_to_add=add_groups,
				groups_to_remove=rm_groups,
			)

		m_add_members_to_groups: MockType = (
			f_connection.extend.microsoft.add_members_to_groups
		)
		m_add_members_to_groups.assert_not_called()
		m_remove_members_from_groups: MockType = (
			f_connection.extend.microsoft.remove_members_from_groups
		)
		m_remove_members_from_groups.assert_not_called()
		assert not m_ldap_user.parsed_specials


class TestPropertyIsEnabled:
	def test_raises_no_entry(
		self,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_ldap_user = f_ldap_user_no_init()
		with pytest.raises(ValueError, match="Entry is required to check"):
			m_ldap_user.is_enabled

	def test_raises_entry_has_no_uac(
		self,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_entry = mocker.Mock()
		m_entry.entry_attributes = {}
		m_ldap_user = f_ldap_user_no_init()
		m_ldap_user.entry = m_entry
		with pytest.raises(ValueError, match="attribute is required in entry"):
			m_ldap_user.is_enabled

	def test_success_mocked(
		self,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_list_user_perms = mocker.patch(
			"core.models.ldap_user.list_user_perms", return_value=True
		)
		m_entry = mocker.Mock()
		m_entry.entry_attributes = [LDAP_ATTR_UAC]
		m_ldap_user = f_ldap_user_no_init(entry=m_entry)

		assert not m_ldap_user.is_enabled
		m_list_user_perms.assert_called_once_with(
			user=m_ldap_user.entry,
			perm_search=LDAP_UF_ACCOUNT_DISABLE,
		)

	@pytest.mark.parametrize(
		"permissions, expected",
		(
			(
				calc_permissions([LDAP_UF_NORMAL_ACCOUNT]),
				True,
			),
			(
				calc_permissions(
					[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_ACCOUNT_DISABLE]
				),
				False,
			),
		),
	)
	def test_success(
		self,
		permissions: list,
		expected: bool,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_entry = mocker.Mock()
		m_entry.entry_attributes = [LDAP_ATTR_UAC]
		m_attr_username = mocker.Mock()
		m_attr_username.value = "testuser"
		m_attr = mocker.Mock()
		setattr(m_entry, LDAP_ATTR_USERNAME_SAMBA_ADDS, m_attr)
		m_attr.value = permissions
		m_attr.values = [permissions]
		setattr(m_entry, LDAP_ATTR_UAC, m_attr)
		m_ldap_user = f_ldap_user_no_init(entry=m_entry)

		assert m_ldap_user.is_enabled == expected


class TestPropertyCanChangePassword:
	def test_raises_no_entry(
		self,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_ldap_user = f_ldap_user_no_init()
		with pytest.raises(ValueError, match="Entry is required to check"):
			m_ldap_user.can_change_password

	def test_raises_entry_has_no_uac(
		self,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_entry = mocker.Mock()
		m_entry.entry_attributes = {}
		m_ldap_user = f_ldap_user_no_init()
		m_ldap_user.entry = m_entry
		with pytest.raises(ValueError, match="attribute is required in entry"):
			m_ldap_user.can_change_password

	def test_success_mocked(
		self,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_list_user_perms = mocker.patch(
			"core.models.ldap_user.list_user_perms", return_value=True
		)
		m_entry = mocker.Mock()
		m_entry.entry_attributes = [LDAP_ATTR_UAC]
		m_ldap_user = f_ldap_user_no_init(entry=m_entry)

		assert not m_ldap_user.can_change_password
		m_list_user_perms.assert_called_once_with(
			user=m_ldap_user.entry,
			perm_search=LDAP_UF_PASSWD_CANT_CHANGE,
		)

	@pytest.mark.parametrize(
		"permissions, expected",
		(
			(
				calc_permissions([LDAP_UF_NORMAL_ACCOUNT]),
				True,
			),
			(
				calc_permissions(
					[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_PASSWD_CANT_CHANGE]
				),
				False,
			),
		),
	)
	def test_success(
		self,
		permissions: list,
		expected: bool,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_entry = mocker.Mock()
		m_entry.entry_attributes = [LDAP_ATTR_UAC]
		m_attr_username = mocker.Mock()
		m_attr_username.value = "testuser"
		m_attr = mocker.Mock()
		setattr(m_entry, LDAP_ATTR_USERNAME_SAMBA_ADDS, m_attr)
		m_attr.value = permissions
		m_attr.values = [permissions]
		setattr(m_entry, LDAP_ATTR_UAC, m_attr)
		m_ldap_user = f_ldap_user_no_init(entry=m_entry)

		assert m_ldap_user.can_change_password == expected
