########################### Standard Pytest Imports ############################
import pytest
################################################################################
from tests.test_core.conftest import RuntimeSettingsFactory
from core.constants.search_attr_builder import SearchAttrBuilder
from core.constants.attrs import local as local_attrs
from core.ldap.defaults import LDAP_FIELD_MAP

LOCAL_ATTRS = [
	getattr(local_attrs, k)
	for k in dir(local_attrs) if k.startswith("LOCAL_ATTR_")
]

@pytest.fixture(autouse=True)
def f_runtime_settings(g_runtime_settings: RuntimeSettingsFactory):
	return g_runtime_settings("core.constants.search_attr_builder")

@pytest.fixture
def f_attr_builder(f_runtime_settings):
	return SearchAttrBuilder(f_runtime_settings)

def test_init_raises_type_error():
	with pytest.raises(TypeError):
		SearchAttrBuilder(False)

class TestToLdap:
	@pytest.mark.parametrize(
		"local_key",
		LDAP_FIELD_MAP.keys(),
	)
	def test_success(
		self,
		f_attr_builder: SearchAttrBuilder,
		f_runtime_settings,
		local_key: str,
	):
		assert f_attr_builder._to_ldap(
			local_key
		) == f_runtime_settings.LDAP_FIELD_MAP[local_key]

	@pytest.mark.parametrize(
		"local_key",
		[k for k in LOCAL_ATTRS if k not in LDAP_FIELD_MAP.keys()],
	)
	def test_raises_unmapped(
		self,
		f_attr_builder: SearchAttrBuilder,
		f_runtime_settings,
		local_key: str,
	):
		with pytest.raises(Exception, match="not find mapped field"):
			f_attr_builder._to_ldap(
				local_key
			) == f_runtime_settings.LDAP_FIELD_MAP[local_key]