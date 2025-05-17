########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType
################################################################################
from core.models.ldap_group import LDAPGroup
from .test_ldap_object import TestDunderValidateInit as SuperDunderValidateInit
from core.type_hints.connector import LDAPConnectionProtocol
from core.ldap.types.group import LDAPGroupTypes
from core.constants.attrs import *
from core.ldap.filter import LDAPFilter, LDAPFilterType
from _pytest.mark.structures import ParameterSet  # pytest's internal type

class TestDunderValidateInit(SuperDunderValidateInit):
	test_cls = LDAPGroup

	def test_only_with_common_name(self, mocker: MockerFixture):
		mocker.patch.object(self.test_cls, "__init__", return_value=None)
		m_ldap_object = self.test_cls()
		m_ldap_object.__validate_init__(**{
			LOCAL_ATTR_NAME: "Test Group"
		})
		result_filter = LDAPFilter.from_string(m_ldap_object.search_filter)
		assert result_filter.children[1].type == LDAPFilterType.EQUALITY
		assert result_filter.children[1].attribute == LDAP_ATTR_COMMON_NAME
		assert result_filter.children[1].value == "Test Group"

def parse_read_group_type_scope_ids(v):
	if isinstance(v, list):
		return ",".join(v)
class TestParseReadGroupTypeScope:
	@pytest.mark.parametrize(
		"v, expected_types, expected_scopes",
		(
			### SECURITY TYPE
			pytest.param(
				# Int to parse
				(
					-LDAPGroupTypes.TYPE_SECURITY.value +
					LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.value
				),
				# Expected results
				[LDAPGroupTypes.TYPE_SECURITY.name],
				[LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.name],
			),
			pytest.param(
				# Int to parse
				(
					-LDAPGroupTypes.TYPE_SECURITY.value +
					LDAPGroupTypes.SCOPE_UNIVERSAL.value
				),
				# Expected results
				[LDAPGroupTypes.TYPE_SECURITY.name],
				[LDAPGroupTypes.SCOPE_UNIVERSAL.name],
			),
			pytest.param(
				# Int to parse
				(
					-LDAPGroupTypes.TYPE_SECURITY.value +
					LDAPGroupTypes.SCOPE_GLOBAL.value
				),
				# Expected results
				[LDAPGroupTypes.TYPE_SECURITY.name],
				[LDAPGroupTypes.SCOPE_GLOBAL.name],
			),
			### DISTRIBUTION TYPE
			pytest.param(
				# Int to parse
				(
					-LDAPGroupTypes.TYPE_DISTRIBUTION.value +
					LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.value
				),
				# Expected results
				[LDAPGroupTypes.TYPE_DISTRIBUTION.name],
				[LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.name],
			),
			pytest.param(
				# Int to parse
				(
					-LDAPGroupTypes.TYPE_DISTRIBUTION.value +
					LDAPGroupTypes.SCOPE_UNIVERSAL.value
				),
				# Expected results
				[LDAPGroupTypes.TYPE_DISTRIBUTION.name],
				[LDAPGroupTypes.SCOPE_UNIVERSAL.name],
			),
			pytest.param(
				# Int to parse
				(
					-LDAPGroupTypes.TYPE_DISTRIBUTION.value +
					LDAPGroupTypes.SCOPE_GLOBAL.value
				),
				# Expected results
				[LDAPGroupTypes.TYPE_DISTRIBUTION.name],
				[LDAPGroupTypes.SCOPE_GLOBAL.name],
			),
			### SECURITY TYPE WITH SYSTEM FLAG
			pytest.param(
				# Int to parse
				(
					-LDAPGroupTypes.TYPE_SECURITY.value +
					LDAPGroupTypes.TYPE_SYSTEM.value +
					LDAPGroupTypes.SCOPE_GLOBAL.value
				),
				# Expected results
				[
					LDAPGroupTypes.TYPE_SECURITY.name,
					LDAPGroupTypes.TYPE_SYSTEM.name,
				],
				[LDAPGroupTypes.SCOPE_GLOBAL.name],
			),
			pytest.param(
				# Int to parse
				(
					-LDAPGroupTypes.TYPE_SECURITY.value +
					LDAPGroupTypes.TYPE_SYSTEM.value +
					LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.value
				),
				# Expected results
				[
					LDAPGroupTypes.TYPE_SECURITY.name,
					LDAPGroupTypes.TYPE_SYSTEM.name,
				],
				[LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.name],
			),
			pytest.param(
				# Int to parse
				(
					-LDAPGroupTypes.TYPE_SECURITY.value +
					LDAPGroupTypes.TYPE_SYSTEM.value +
					LDAPGroupTypes.SCOPE_UNIVERSAL.value
				),
				# Expected results
				[
					LDAPGroupTypes.TYPE_SECURITY.name,
					LDAPGroupTypes.TYPE_SYSTEM.name,
				],
				[LDAPGroupTypes.SCOPE_UNIVERSAL.name],
			),
			### DISTRIBUTION TYPE WITH SYSTEM FLAG
			pytest.param(
				# Int to parse
				(
					-LDAPGroupTypes.TYPE_DISTRIBUTION.value +
					LDAPGroupTypes.TYPE_SYSTEM.value +
					LDAPGroupTypes.SCOPE_GLOBAL.value
				),
				# Expected results
				[
					LDAPGroupTypes.TYPE_DISTRIBUTION.name,
					LDAPGroupTypes.TYPE_SYSTEM.name,
				],
				[LDAPGroupTypes.SCOPE_GLOBAL.name],
			),
			pytest.param(
				# Int to parse
				(
					-LDAPGroupTypes.TYPE_DISTRIBUTION.value +
					LDAPGroupTypes.TYPE_SYSTEM.value +
					LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.value
				),
				# Expected results
				[
					LDAPGroupTypes.TYPE_DISTRIBUTION.name,
					LDAPGroupTypes.TYPE_SYSTEM.name,
				],
				[LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.name],
			),
			pytest.param(
				# Int to parse
				(
					-LDAPGroupTypes.TYPE_DISTRIBUTION.value +
					LDAPGroupTypes.TYPE_SYSTEM.value +
					LDAPGroupTypes.SCOPE_UNIVERSAL.value
				),
				# Expected results
				[
					LDAPGroupTypes.TYPE_DISTRIBUTION.name,
					LDAPGroupTypes.TYPE_SYSTEM.name,
				],
				[LDAPGroupTypes.SCOPE_UNIVERSAL.name],
			),
		),
		ids=parse_read_group_type_scope_ids
	)
	def test_success(
		self,
		mocker: MockerFixture,
		v,
		expected_types,
		expected_scopes
	):
		mocker.patch.object(LDAPGroup, "__init__", return_value=None)
		m_ldap_object = LDAPGroup()
		group_types, group_scopes = m_ldap_object.parse_read_group_type_scope(v)
		assert group_types == expected_types
		assert group_scopes == expected_scopes

	def test_success_from_str(self, mocker: MockerFixture):
		mocker.patch.object(LDAPGroup, "__init__", return_value=None)
		m_ldap_object = LDAPGroup()
		group_types, group_scopes = m_ldap_object.parse_read_group_type_scope(
			str(LDAPGroupTypes.TYPE_DISTRIBUTION.value + LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.value)
		)
		assert group_types == [LDAPGroupTypes.TYPE_DISTRIBUTION.name]
		assert group_scopes == [LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.name]

	def test_raises_from_str(self, mocker: MockerFixture):
		mocker.patch.object(LDAPGroup, "__init__", return_value=None)
		m_ldap_object = LDAPGroup()
		with pytest.raises(ValueError, match="could not be cast"):
			m_ldap_object.parse_read_group_type_scope(
				"some_str"
			)

	@pytest.mark.parametrize(
		"bad_value",
		(
			b"some_bytes",
			False,
			None,
			True,
		),
	)
	def test_raises_type_error(self, mocker: MockerFixture, bad_value):
		mocker.patch.object(LDAPGroup, "__init__", return_value=None)
		m_ldap_object = LDAPGroup()
		with pytest.raises(TypeError, match="must be of type"):
			m_ldap_object.parse_read_group_type_scope(bad_value)

	def test_raises_from_invalid_int(self, mocker: MockerFixture):
		mocker.patch.object(LDAPGroup, "__init__", return_value=None)
		m_ldap_object = LDAPGroup()
		with pytest.raises(ValueError, match="group type integer calculation"):
			m_ldap_object.parse_read_group_type_scope(1234)

class TestParseWriteGroupTypeScope:
	pass