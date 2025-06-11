########################### Standard Pytest Imports ############################
import pytest
################################################################################
from core.views.mixins.user.utils import UserUtilsMixin, ALL_LOCAL_ATTRS
from core.constants.attrs import *
from core.exceptions import base as exc_base, users as exc_user
from core.models.ldap_user import DEFAULT_LOCAL_ATTRS

@pytest.fixture
def f_mixin():
	return UserUtilsMixin()

@pytest.mark.django_db
class TestGetLdapBackendEnabled:
	def test_enabled(
		self, f_mixin: UserUtilsMixin, g_interlock_ldap_enabled
	):
		f_mixin.get_ldap_backend_enabled()
		assert f_mixin.ldap_backend_enabled

	def test_disabled(
		self, f_mixin: UserUtilsMixin, g_interlock_ldap_disabled
	):
		f_mixin.get_ldap_backend_enabled()
		assert not f_mixin.ldap_backend_enabled

	def test_disabled_on_not_exists(self, f_mixin: UserUtilsMixin):
		f_mixin.get_ldap_backend_enabled()
		assert not f_mixin.ldap_backend_enabled

class TestValidateLocalAttrs:
	def test_with_defaults(self, f_mixin: UserUtilsMixin):
		assert f_mixin.validate_local_attrs([
			LOCAL_ATTR_USERNAME, # User Attr
			LOCAL_ATTR_CAN_CHANGE_PWD, # User Property Attr
			LOCAL_ATTR_GROUP_MEMBERS, # Group Attr
		]) is None
	
	def test_invalid_attr_raises(self, f_mixin: UserUtilsMixin):
		with pytest.raises(exc_base.BadRequest):
			f_mixin.validate_local_attrs(["some_bad_attr"])
	
	def test_with_user_attrs_raises(self, f_mixin: UserUtilsMixin):
		with pytest.raises(exc_base.BadRequest):
			f_mixin.validate_local_attrs(
				[
					LOCAL_ATTR_USERNAME, # User Attr
					LOCAL_ATTR_CAN_CHANGE_PWD, # User Property Attr
					LOCAL_ATTR_GROUP_MEMBERS, # Group Attr
				],
				check_attrs=DEFAULT_LOCAL_ATTRS
			)

class TestValidateCsvHeaders:
	@pytest.fixture
	def m_csv_map(self):
		return {
			LOCAL_ATTR_USERNAME: "nombreusuario",
			LOCAL_ATTR_EMAIL: "correo",
			LOCAL_ATTR_ADDRESS: "direccion",
		}.copy()

	def test_raises_headers_not_list(self, f_mixin: UserUtilsMixin):
		with pytest.raises(exc_user.UserBulkInsertMappingError) as e:
			f_mixin.validate_csv_headers(
				headers=None,
			)
		assert "must be of type list" in e.value.detail.get("detail")

	def test_raises_csv_map_not_dict(self, f_mixin: UserUtilsMixin):
		with pytest.raises(exc_user.UserBulkInsertMappingError) as e:
			f_mixin.validate_csv_headers(
				headers=["somevalue"],
				csv_map="a_string_should_raise",
			)
		assert "must be of type dict" in e.value.detail.get("detail")

	def test_with_headers_only(self, f_mixin: UserUtilsMixin):
		assert f_mixin.validate_csv_headers(
			headers=[LOCAL_ATTR_USERNAME, LOCAL_ATTR_EMAIL, LOCAL_ATTR_ADDRESS]
		) is None

	def test_raises_no_username_with_headers_only(
		self,
		f_mixin: UserUtilsMixin,
	):
		with pytest.raises(exc_user.UserBulkInsertMappingError) as e:
			f_mixin.validate_csv_headers(
				headers=[LOCAL_ATTR_EMAIL, LOCAL_ATTR_ADDRESS]
			)
		assert "is required in mapping" in e.value.detail.get("detail")

	def test_with_mapping(self, f_mixin: UserUtilsMixin, m_csv_map: dict):
		assert f_mixin.validate_csv_headers(
			headers=list(m_csv_map.values()),
			csv_map=m_csv_map,
		) is None

	def test_mapping_length_conflict_raises(
		self,
		f_mixin: UserUtilsMixin,
		m_csv_map: dict,
	):
		m_headers = list(m_csv_map.values())
		m_headers.pop(-1)
		with pytest.raises(exc_user.UserBulkInsertMappingError) as e:
			f_mixin.validate_csv_headers(
				headers=m_headers,
				csv_map=m_csv_map,
			)
		assert "length mismatch" in e.value.detail.get("detail")

	def test_mapping_no_username_key_raises(
		self,
		f_mixin: UserUtilsMixin,
		m_csv_map: dict,
	):
		del m_csv_map[LOCAL_ATTR_USERNAME]
		m_headers = list(m_csv_map.values())
		with pytest.raises(exc_user.UserBulkInsertMappingError) as e:
			f_mixin.validate_csv_headers(
				headers=m_headers,
				csv_map=m_csv_map,
			)
		assert "is required in mapping" in e.value.detail.get("detail")

	def test_mapping_not_in_headers_raises(
		self,
		f_mixin: UserUtilsMixin,
		m_csv_map: dict,
	):
		m_headers = list(m_csv_map.values())
		m_headers[-1] = "somevalue"
		with pytest.raises(exc_user.UserBulkInsertMappingError) as e:
			f_mixin.validate_csv_headers(
				headers=m_headers,
				csv_map=m_csv_map,
			)
		assert "Unmapped key" in e.value.detail.get("detail")

class TestValidateAndMapCsvHeaders:
	def test_success_no_csv_map(self, f_mixin: UserUtilsMixin):
		result = f_mixin.validate_and_map_csv_headers(
			[
				LOCAL_ATTR_USERNAME,
				LOCAL_ATTR_EMAIL,
			]
		)
		assert result == {0: LOCAL_ATTR_USERNAME, 1: LOCAL_ATTR_EMAIL}

	def test_success_with_csv_map(self, f_mixin: UserUtilsMixin):
		result = f_mixin.validate_and_map_csv_headers(
			headers=[
				"nombreusuario",
				"correo",
			],
			csv_map={
				LOCAL_ATTR_USERNAME: "nombreusuario",
				LOCAL_ATTR_EMAIL: "correo",
			},
		)
		assert isinstance(result, dict)
		assert result == {0: LOCAL_ATTR_USERNAME, 1: LOCAL_ATTR_EMAIL}


class TestCleanupEmptyStrValues:
	def test_deletion(self, f_mixin: UserUtilsMixin):
		m_dct = {
			"a": "value",
			"b": "",
		}
		expected = m_dct.copy()
		expected.pop("b")
		assert f_mixin.cleanup_empty_str_values(m_dct) == expected
