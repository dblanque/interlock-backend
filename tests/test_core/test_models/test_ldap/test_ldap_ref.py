########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture
################################################################################
from core.models.ldap_ref import LdapRef
from core.constants.attrs.ldap import LDAP_ATTR_SECURITY_ID, LDAP_ATTR_DN
from tests.test_core.conftest import ConnectorFactory, LDAPConnectorMock
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from core.ldap.filter import LDAPFilter

@pytest.fixture(autouse=True)
def f_ldap_connector(g_ldap_connector: ConnectorFactory) -> LDAPConnectorMock:
	return g_ldap_connector()

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

	def test_success(
		self,
		f_ldap_connector: LDAPConnectorMock,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		f_ldap_connector.connection.entries = ["result"]
		result = LdapRef.get_entry_from_ldap(
			connection=f_ldap_connector.connection, # type: ignore
			pk="mock_sid",
		)
		f_ldap_connector.connection.search.assert_called_once_with(
			search_base=f_runtime_settings.LDAP_AUTH_SEARCH_BASE,
			search_filter=LDAPFilter.eq(
				LDAP_ATTR_SECURITY_ID, "mock_sid").to_string(),
			attributes=[LDAP_ATTR_DN, LDAP_ATTR_SECURITY_ID],
			size_limit=1
		)
		assert result == "result"

	def test_returns_none_on_no_entries(
		self,
		f_ldap_connector: LDAPConnectorMock,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		f_ldap_connector.connection.entries = []
		result = LdapRef.get_entry_from_ldap(
			connection=f_ldap_connector.connection, # type: ignore
			pk="mock_sid",
		)
		f_ldap_connector.connection.search.assert_called_once_with(
			search_base=f_runtime_settings.LDAP_AUTH_SEARCH_BASE,
			search_filter=LDAPFilter.eq(
				LDAP_ATTR_SECURITY_ID, "mock_sid").to_string(),
			attributes=[LDAP_ATTR_DN, LDAP_ATTR_SECURITY_ID],
			size_limit=1
		)
		assert result == None


class TestGetInstanceFromLdap:
	def test_not_implemented(self):
		raise NotImplementedError

	def test_no_connection_raises(self):
		with pytest.raises(ValueError, match="connection is"):
			LdapRef.get_instance_from_ldap(
				distinguished_name=None,
				connection=None,
			)

	def test_no_distinguished_name_raises(
		self,
		f_ldap_connector: LDAPConnectorMock,
	):
		with pytest.raises(ValueError, match="distinguished_name is"):
			LdapRef.get_instance_from_ldap(
				distinguished_name=None,
				connection=f_ldap_connector.connection,
			)

class TestRefreshFromLdap:
	def test_not_implemented(self):
		raise NotImplementedError

class TestPrune:
	def test_pruned(
		self,
		mocker: MockerFixture,
		f_ldap_ref: LdapRef,
		f_ldap_connector: LDAPConnectorMock,
	):
		conn = f_ldap_connector.connection
		pk = f_ldap_ref.pk
		sid = f_ldap_ref.object_security_id
		m_get_entry_from_ldap = mocker.patch.object(
			f_ldap_ref,
			"get_entry_from_ldap",
			return_value=None
		)
		f_ldap_ref.prune(connection=conn)
		m_get_entry_from_ldap.assert_called_once_with(connection=conn, pk=sid)
		with pytest.raises(LdapRef.DoesNotExist):
			LdapRef.objects.get(pk=pk)

	def test_not_pruned(
		self,
		mocker: MockerFixture,
		f_ldap_ref: LdapRef,
		f_ldap_connector: LDAPConnectorMock,
	):
		conn = f_ldap_connector.connection
		m_get_entry_from_ldap = mocker.patch.object(
			f_ldap_ref,
			"get_entry_from_ldap",
			return_value="mock_entry"
		)
		f_ldap_ref.prune(connection=conn)
		m_get_entry_from_ldap.assert_called_once_with(
			connection=conn,
			pk=f_ldap_ref.object_security_id,
		)
		assert LdapRef.objects.get(pk=f_ldap_ref.pk).pk == f_ldap_ref.pk

class TestRefreshOrPrune:
	@pytest.mark.parametrize(
		"refresh_return, prune_return, expected",
		(
			(True, None, True),
			(False, True, False),
			(False, False, True),
		),
	)
	def test_success(
		self,
		mocker: MockerFixture,
		f_ldap_ref: LdapRef,
		f_ldap_connector: LDAPConnectorMock,
		refresh_return: bool,
		prune_return: bool,
		expected: bool,
	):
		conn = f_ldap_connector.connection
		m_refresh = mocker.patch.object(
			f_ldap_ref, "refresh_from_ldap", return_value=refresh_return)
		m_prune = mocker.patch.object(
			f_ldap_ref, "prune", return_value=prune_return)
		assert f_ldap_ref.refresh_or_prune(
			connection=conn
		) == expected
		m_refresh.assert_called_once_with(connection=conn)
		if not refresh_return:
			m_prune.assert_called_once_with(connection=conn)
		else:
			m_prune.assert_not_called()
