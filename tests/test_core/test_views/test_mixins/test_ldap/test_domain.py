########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType
################################################################################
from core.models.user import User
from core.models.dns import LDAPRecord, DATE_FMT
from core.ldap.connector import LDAPConnector
from core.ldap.defaults import LDAP_DOMAIN
from core.views.mixins.ldap.domain import DomainViewMixin
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from core.views.mixins.logs import LogMixin
from core.models.choices.log import LOG_ACTION_READ, LOG_CLASS_DNSZ
from datetime import datetime
from typing import Protocol
from core.models.dns import RecordTypes

@pytest.fixture(autouse=True)
def f_log_mixin(mocker: MockerFixture) -> LogMixin:
	return mocker.patch("core.views.mixins.ldap.domain.DBLogMixin")

@pytest.fixture(autouse=True)
def f_runtime_settings(mocker: MockerFixture, g_runtime_settings):
	mocker.patch("core.views.mixins.ldap.domain.RuntimeSettings", g_runtime_settings)
	return g_runtime_settings

@pytest.fixture(autouse=True)
def f_ldap_connector(g_ldap_connector):
	return g_ldap_connector(
		patch_path="core.views.mixins.ldap.domain.LDAPConnector",
	)

@pytest.fixture
def f_domain_mixin(mocker: MockerFixture):
	mixin = DomainViewMixin()
	mixin.connection = mocker.MagicMock()
	return mixin


@pytest.fixture
def f_mock_soa_record(mocker: MockerFixture):
	mock = mocker.MagicMock(spec=LDAPRecord)
	mock.data = {"dwSerialNo": 100, "serial": 100}
	return mock

@pytest.fixture
def f_record_entry(mocker: MockerFixture):
	m_entry = mocker.Mock()
	m_entry.name.value = "subdomain"
	m_entry.entry_dn = "record_entry_dn"
	m_entry.dnsRecord.values = [b"mock_record_bytes"]
	return m_entry

class LDAPRecordFactoryProtocol(Protocol):
	def __call__(self) -> tuple[MockType, MockType]: ...
	"""Returns a tuple of (m_cls, m_instance)"""

@pytest.fixture
def fc_ldap_record(mocker: MockerFixture) -> LDAPRecordFactoryProtocol:
	def maker():
		m_instance = mocker.Mock(name="mock_LDAPRecord_instance")
		m_cls = mocker.Mock(name="mock_LDAPRecord_cls", return_value=m_instance)
		mocker.patch("core.views.mixins.ldap.domain.LDAPRecord", m_cls)
		return m_cls, m_instance
	return maker

class TestUtils:
	def test_get_zone_soa(self, f_domain_mixin: DomainViewMixin, f_mock_soa_record: LDAPRecord, mocker):
		mocker.patch(
			"core.views.mixins.ldap.domain.LDAPRecord",
			return_value=f_mock_soa_record,
		)

		result = f_domain_mixin.get_zone_soa(LDAP_DOMAIN)
		assert result == f_mock_soa_record.data

	def test_increment_soa_serial(self, f_domain_mixin: DomainViewMixin, f_mock_soa_record: LDAPRecord):
		result = f_domain_mixin.increment_soa_serial(f_mock_soa_record, 101)
		f_mock_soa_record.update.assert_called_once()

	@staticmethod
	@pytest.mark.parametrize(
		"as_epoch, expected",
		(
			(True, int(datetime.today().strftime(DATE_FMT) + "01")),
			(False, 1),
		),
	)
	def test_create_initial_serial(as_epoch: bool, expected: int, f_domain_mixin: DomainViewMixin):
		assert f_domain_mixin.create_initial_serial(
			as_epoch_serial=as_epoch
		) == expected

class TestGetZoneRecords:
	def test_get_zone_records(
		self,
		mocker: MockerFixture,
		f_domain_mixin: DomainViewMixin,
		admin_user: User,
		f_ldap_connector: LDAPConnector,
		f_runtime_settings: RuntimeSettingsSingleton,
		f_log_mixin: LogMixin,
		f_record_entry,
	):
		m_entry = f_record_entry
		# Mock LDAPDNS
		m_ldap_dns_instance = mocker.Mock()
		m_ldap_dns_instance.dns_root = "fake_root"
		m_ldap_dns_instance.dns_zones = ["RootDNSServers", f_runtime_settings.LDAP_DOMAIN]
		m_ldap_dns_instance.forest_zones = ["mock_forest_zone"]
		m_ldap_dns = mocker.patch(
			"core.views.mixins.ldap.domain.LDAPDNS",
			return_value=m_ldap_dns_instance
		)

		# Mock Inner Functions
		m_get_ttl = mocker.Mock(return_value=180)
		m_DNS_RECORD_instance = mocker.Mock()
		m_DNS_RECORD_instance.__getTTL__ = m_get_ttl
		m_DNS_RECORD = mocker.patch(
			"core.views.mixins.ldap.domain.dnstool.DNS_RECORD",
			return_value=m_DNS_RECORD_instance
		)
		m_record_dict = {}
		m_record_to_dict = mocker.patch(
			"core.views.mixins.ldap.domain.record_to_dict",
			return_value=m_record_dict
		)
		m_getldapattrvalue = mocker.patch(
			"core.views.mixins.ldap.domain.getldapattrvalue",
			side_effect=[b"mock_name", False]
		)
		m_dnsRecord = mocker.Mock()
		m_record_in_entry = "mock_record"
		m_dnsRecord.values = ["mock_record"]
		m_getldapattr = mocker.patch("core.views.mixins.ldap.domain.getldapattr", return_value=m_dnsRecord)
		f_ldap_connector.connection.entries = [m_entry]

		# Execution
		result = f_domain_mixin.get_zone_records(
			user=admin_user,
			target_zone=f_runtime_settings.LDAP_DOMAIN
		)

		# Assertions
		f_ldap_connector.connection.search.assert_called_once_with(
			search_base=f"DC={f_runtime_settings.LDAP_DOMAIN},fake_root",
			search_filter="(objectClass=dnsNode)",
			attributes=["dnsRecord", "dNSTombstoned", "name"],
		)
		m_DNS_RECORD.assert_called_once_with(m_record_in_entry)
		m_ldap_dns.assert_called_once_with(f_ldap_connector.connection)
		m_getldapattrvalue.call_count == 2
		m_getldapattrvalue.assert_any_call(m_entry, "name")
		m_getldapattrvalue.assert_any_call(m_entry, "dNSTombstoned")
		m_getldapattr.assert_called_once_with(m_entry, "dnsRecord")
		m_get_ttl.assert_called_once()
		m_record_to_dict.assert_called_once_with(
			record=m_DNS_RECORD_instance,
			ts=False
		)
		f_log_mixin.log.assert_called_once_with(
			user=admin_user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_DNSZ,
			log_target=f_runtime_settings.LDAP_DOMAIN,
		)
		for k in ("dnsZones", "forestZones", "records", "legacy",):
			assert k in result
		assert set(result["headers"]) == set(['name', 'value', 'ttl', 'typeName', 'serial'])
		assert result["dnsZones"] == ["Root DNS Servers", f_runtime_settings.LDAP_DOMAIN]
		assert result["forestZones"] == ["mock_forest_zone"]
		assert not result["legacy"]
		assert result["records"] == [m_record_dict]

class TestRecordTemplateInsertions:
	def test_insert_soa(
		self,
		f_domain_mixin: DomainViewMixin,
		f_runtime_settings: RuntimeSettingsSingleton,
		fc_ldap_record,
	):
		f_domain_mixin.connection.result = "mock_result"
		m_ldap_record, m_ldap_record_instance = fc_ldap_record()
		result = f_domain_mixin.insert_soa(
			connection=f_domain_mixin.connection,
			target_zone=f_runtime_settings.LDAP_DOMAIN,
			ttl=180,
			serial=1,
		)

		# Assertions
		m_ldap_record.assert_called_once_with(
			connection=f_domain_mixin.connection,
			record_name="@",
			record_zone=f_runtime_settings.LDAP_DOMAIN,
			record_type=RecordTypes.DNS_RECORD_TYPE_SOA.value,
			record_main_value=f"ns.{f_runtime_settings.LDAP_DOMAIN}.",
		)
		m_ldap_record_instance.create.assert_called_once_with(
			values={
			"ttl": 180,
			"serial": 1,
			# SOA Specific
			"dwSerialNo": 1,
			"dwRefresh": 900,
			"dwRetry": 600,
			"dwExpire": 86400,
			"dwMinimumTtl": 180,
			"namePrimaryServer": f"ns.{f_runtime_settings.LDAP_DOMAIN}.",
			"zoneAdminEmail": f"hostmaster.{f_runtime_settings.LDAP_DOMAIN}",
		})
		assert result == "mock_result"

	def test_insert_ns_a(
		self,
		f_domain_mixin: DomainViewMixin,
	):
		pass

	def test_insert_ns_aaaa(
		self,
		f_domain_mixin: DomainViewMixin,
	):
		pass

	def test_insert_ns(
		self,
		f_domain_mixin: DomainViewMixin,
	):
		pass

