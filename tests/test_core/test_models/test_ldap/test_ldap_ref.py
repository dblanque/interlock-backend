########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture
################################################################################
from core.models.ldap_ref import LdapRef
from core.constants.attrs.ldap import LDAP_ATTR_SECURITY_ID, LDAP_ATTR_DN
from tests.test_core.conftest import ConnectorFactory, LDAPConnectorMock

@pytest.fixture
def f_ldap_connector(g_ldap_connector: ConnectorFactory) -> LDAPConnectorMock:
	return g_ldap_connector(patch_path="core.models.ldap_ref.LDAPConnector")

@pytest.fixture
def f_ldap_ref():
	ldap_ref = LdapRef(
		distinguished_name="CN=some_ldap_ref,DC=example,DC=com",
		object_security_id_bytes=b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x11^\xb3\x83j\x06\x94\x00\x80\xdbi\xaa\x87\x04\x00\x00",
		object_security_id="S-1-5-21-2209570321-9700970-2859064192-1159",
	)
	ldap_ref.save()
	return ldap_ref

class TestGetRelativeId:
	def test_success(self, f_ldap_ref: LdapRef):
		assert f_ldap_ref.get_relative_id() == 1159

	def test_no_sid_str(self, f_ldap_ref: LdapRef):
		f_ldap_ref.object_security_id = ""
		assert f_ldap_ref.get_relative_id() == 1159

	def test_no_sid(self, f_ldap_ref: LdapRef):
		f_ldap_ref.object_security_id = ""
		f_ldap_ref.object_security_id_bytes = None # type: ignore
		assert f_ldap_ref.get_relative_id() == 0

class TestObjectRelativeIdProperty:
	def test_success(self, mocker: MockerFixture, f_ldap_ref: LdapRef):
		m_get_relative_id = mocker.patch.object(
			f_ldap_ref, "get_relative_id", return_value=1159)
		assert f_ldap_ref.object_relative_id == 1159
		m_get_relative_id.assert_called_once()

class TestStaticFieldMethods:
	def test_get_dn_field_defaults(self, f_ldap_ref: LdapRef):
		assert f_ldap_ref.get_dn_field() == LDAP_ATTR_DN

	def test_get_sid_field_defaults(self, f_ldap_ref: LdapRef):
		assert f_ldap_ref.get_sid_field() == LDAP_ATTR_SECURITY_ID

class TestGetEntryFromLdap:
	def test_not_implemented(self):
		raise NotImplementedError
	
	def test_no_connection_raises(self):
		with pytest.raises(ValueError, match="connection is"):
			LdapRef.get_entry_from_ldap(
				connection=None,
				pk="",
			)
	
	def test_no_pk_raises(self, f_ldap_connector: LDAPConnectorMock):
		with pytest.raises(ValueError, match="pk is"):
			LdapRef.get_entry_from_ldap(
				connection=f_ldap_connector.connection, # type: ignore
				pk="",
			)
	
	def test_bad_ident_raises(self, f_ldap_connector: LDAPConnectorMock):
		with pytest.raises(ValueError, match="must be a valid"):
			LdapRef.get_entry_from_ldap(
				connection=f_ldap_connector.connection, # type: ignore
				pk="abcd",
				pk_ident="bad_value",
			)

class TestGetInstanceFromLdap:
	def test_not_implemented(self):
		raise NotImplementedError

class TestRefreshFromLdap:
	def test_not_implemented(self):
		raise NotImplementedError

class TestPrune:
	def test_not_implemented(self):
		raise NotImplementedError

class TestRefreshOrPrune:
	def test_not_implemented(self):
		raise NotImplementedError