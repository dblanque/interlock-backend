########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType
################################################################################
from core.serializers.group import (
	LDAPGroupSerializer,
	group_type_validator,
	group_scope_validator,
)
from rest_framework.serializers import ValidationError
from core.constants.attrs.local import (
	LOCAL_ATTR_NAME,
	LOCAL_ATTR_COMMON_NAME,
	LOCAL_ATTR_DN,
	LOCAL_ATTR_EMAIL,
	LOCAL_ATTR_GROUP_TYPE,
	LOCAL_ATTR_GROUP_SCOPE,
	LOCAL_ATTR_OBJECT_CLASS,
	LOCAL_ATTR_OBJECT_CATEGORY,
	LOCAL_ATTR_SECURITY_ID,
	LOCAL_ATTR_RELATIVE_ID,
	LOCAL_ATTR_GROUP_MEMBERS,
	LOCAL_ATTR_GROUP_ADD_MEMBERS,
	LOCAL_ATTR_GROUP_RM_MEMBERS,
)
from core.models.ldap_group import LDAPGroupTypes

@pytest.fixture
def fc_group_data():
	def maker(**kwargs):
		return {
			LOCAL_ATTR_NAME: "Test Group",
			LOCAL_ATTR_DN: "CN=Test Group,DC=example,DC=com",
			LOCAL_ATTR_EMAIL: "email@example.com",
			LOCAL_ATTR_GROUP_TYPE: [LDAPGroupTypes.TYPE_SECURITY.name],
			LOCAL_ATTR_GROUP_SCOPE: [LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.name],
			LOCAL_ATTR_OBJECT_CLASS: ["top","group"],
			LOCAL_ATTR_OBJECT_CATEGORY: "group",
			LOCAL_ATTR_SECURITY_ID: "S-1-5-21-2209570321-9700970-2859064192-1159",
			LOCAL_ATTR_RELATIVE_ID: 1159,
			LOCAL_ATTR_GROUP_MEMBERS: [],
			LOCAL_ATTR_GROUP_ADD_MEMBERS: [],
			LOCAL_ATTR_GROUP_RM_MEMBERS: [],
		} | kwargs
	return maker

@pytest.fixture
def f_group_data(fc_group_data):
	return fc_group_data()

@pytest.fixture
def f_group_data_with_cn(fc_group_data):
	_group = fc_group_data()
	_group[LOCAL_ATTR_COMMON_NAME] = _group.pop(LOCAL_ATTR_NAME)
	return _group

class TestGroupTypeValidator:
	@pytest.mark.parametrize(
		"group_type",
		(
			LDAPGroupTypes.TYPE_DISTRIBUTION.name,
			LDAPGroupTypes.TYPE_SECURITY.name,
			LDAPGroupTypes.TYPE_SYSTEM.name,
		),
	)
	def test_success(self, group_type):
		assert group_type_validator(group_type) is None

	@pytest.mark.parametrize(
		"value, expected_match",
		(
			(1, "Group Type is invalid"),
			(LDAPGroupTypes.SCOPE_GLOBAL.name, "Group Scope cannot be set"),
		),
	)
	def test_raises(self, value, expected_match):
		with pytest.raises(ValidationError, match=expected_match):
			group_type_validator(value)

class TestGroupScopeValidator:
	@pytest.mark.parametrize(
		"group_scope",
		(
			LDAPGroupTypes.SCOPE_GLOBAL.name,
			LDAPGroupTypes.SCOPE_UNIVERSAL.name,
			LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.name,
		),
	)
	def test_success(self, group_scope):
		assert group_scope_validator(group_scope) is None

	@pytest.mark.parametrize(
		"value, expected_match",
		(
			(1, "Group Scope is invalid"),
			(LDAPGroupTypes.TYPE_SYSTEM.name, "Group Type cannot be set"),
		),
	)
	def test_raises(self, value, expected_match):
		with pytest.raises(ValidationError, match=expected_match):
			group_scope_validator(value)

class TestSerializer:
	@pytest.mark.parametrize(
		"group_data_fixture",
		(
			"f_group_data",
			"f_group_data_with_cn",
		),
	)
	def test_full_success_with_name(
		self,
		request: FixtureRequest,
		group_data_fixture: str
	):
		serializer = LDAPGroupSerializer(
			data=request.getfixturevalue(group_data_fixture)
		)
		is_valid = serializer.is_valid()
		_data = serializer.validated_data
		assert _data.get(LOCAL_ATTR_NAME) == _data.get(LOCAL_ATTR_COMMON_NAME)
		assert is_valid

	def test_raises_invalid_type(self, f_group_data: dict):
		f_group_data[LOCAL_ATTR_GROUP_TYPE] = 1
		serializer = LDAPGroupSerializer(data=f_group_data)
		is_valid = serializer.is_valid()
		assert not is_valid
		assert set(serializer.errors.keys()) == {LOCAL_ATTR_GROUP_TYPE}

	def test_raises_invalid_scope(self, f_group_data: dict):
		f_group_data[LOCAL_ATTR_GROUP_SCOPE] = 1
		serializer = LDAPGroupSerializer(data=f_group_data)
		is_valid = serializer.is_valid()
		assert not is_valid
		assert set(serializer.errors.keys()) == {LOCAL_ATTR_GROUP_SCOPE}

	@pytest.mark.parametrize(
		"field_to_pop",
		(
			LOCAL_ATTR_GROUP_TYPE,
			LOCAL_ATTR_GROUP_SCOPE,
		),
	)
	def test_raises_on_missing_field(
		self,
		f_group_data: dict,
		field_to_pop: str
	):
		f_group_data.pop(field_to_pop)
		serializer = LDAPGroupSerializer(data=f_group_data)
		is_valid = serializer.is_valid()
		assert not is_valid
		assert "updates require" in serializer.errors[LOCAL_ATTR_GROUP_TYPE][0]
		assert set(serializer.errors.keys()) == {LOCAL_ATTR_GROUP_TYPE}
