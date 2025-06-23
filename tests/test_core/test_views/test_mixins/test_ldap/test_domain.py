########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture, MockType

################################################################################
from core.models.user import User
from core.models.dns import LDAPRecord, DATE_FMT
from core.ldap.connector import LDAPConnector
from core.ldap.defaults import LDAP_DOMAIN
from core.constants.attrs.local import LOCAL_ATTR_VALUE
from core.constants.attrs.ldap import LDAP_ATTR_DN
from core.constants.dns import (
	LDNS_ATTR_ENTRY_RECORD,
	LDNS_ATTR_ENTRY_NAME,
	LDNS_ATTR_ENTRY_DISPLAY_NAME,  # Custom Header, attr not in LDAP
	LDNS_ATTR_TTL,
	LDNS_ATTR_TYPE_NAME,
	LDNS_ATTR_SERIAL,
)
from core.views.mixins.ldap.domain import DomainViewMixin
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from tests.test_core.conftest import RuntimeSettingsFactory
from core.views.mixins.logs import LogMixin
from core.models.choices.log import (
	LOG_ACTION_READ,
	LOG_ACTION_CREATE,
	LOG_ACTION_DELETE,
	LOG_CLASS_DNSZ,
)
from core.exceptions import dns as exc_dns
from datetime import datetime
from typing import Protocol
from core.models.dns import RecordTypes
from ldap3 import LEVEL as ldap3_LEVEL
from logging import Logger
from tests.test_core.conftest import (
	LDAPEntryFactoryProtocol,
)


@pytest.fixture
def f_logger(mocker: MockerFixture):
	return mocker.patch("core.views.mixins.ldap.domain.logger")


@pytest.fixture(autouse=True)
def f_log_mixin(mocker: MockerFixture) -> LogMixin:
	return mocker.patch("core.views.mixins.ldap.domain.DBLogMixin")


@pytest.fixture(autouse=True)
def f_runtime_settings(g_runtime_settings: RuntimeSettingsFactory):
	return g_runtime_settings("core.views.mixins.ldap.domain.RuntimeSettings")


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
def f_record_entry(fc_ldap_entry: LDAPEntryFactoryProtocol):
	m_entry = fc_ldap_entry(
		**{
			LDNS_ATTR_ENTRY_NAME: "subdomain",
			LDAP_ATTR_DN: "mock_record_dn",
			LDNS_ATTR_ENTRY_RECORD: b"mock_record_bytes",
		}
	)
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
	def test_get_zone_soa(
		self,
		f_domain_mixin: DomainViewMixin,
		f_mock_soa_record: LDAPRecord,
		mocker,
	):
		mocker.patch(
			"core.views.mixins.ldap.domain.LDAPRecord",
			return_value=f_mock_soa_record,
		)

		result = f_domain_mixin.get_zone_soa(LDAP_DOMAIN)
		assert result == f_mock_soa_record.data

	def test_increment_soa_serial(
		self, f_domain_mixin: DomainViewMixin, f_mock_soa_record: LDAPRecord
	):
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
	def test_create_initial_serial(
		as_epoch: bool, expected: int, f_domain_mixin: DomainViewMixin
	):
		assert (
			f_domain_mixin.create_initial_serial(as_epoch_serial=as_epoch)
			== expected
		)


class TestGetZoneRecords:
	def test_raises_search_exception(
		self,
		mocker: MockerFixture,
		f_domain_mixin: DomainViewMixin,
		admin_user: User,
		f_ldap_connector: LDAPConnector,
		f_runtime_settings: RuntimeSettingsSingleton,
		f_logger: Logger,
	):
		# Mock LDAPDNS
		m_ldap_dns_instance = mocker.Mock()
		m_ldap_dns_instance.dns_root = "fake_root"
		m_ldap_dns_instance.dns_zones = [
			"RootDNSServers",
			f_runtime_settings.LDAP_DOMAIN,
		]
		m_ldap_dns_instance.forest_zones = ["mock_forest_zone"]
		mocker.patch(
			"core.views.mixins.ldap.domain.LDAPDNS",
			return_value=m_ldap_dns_instance,
		)
		m_exception = Exception()
		f_ldap_connector.connection.search.side_effect = m_exception
		with pytest.raises(Exception):
			f_domain_mixin.get_zone_records(
				user=admin_user, target_zone=f_runtime_settings.LDAP_DOMAIN
			)
		f_logger.exception.assert_called_once_with(m_exception)
		f_logger.error.assert_any_call(
			f"DC={f_runtime_settings.LDAP_DOMAIN},fake_root"
		)
		f_logger.error.assert_any_call("(objectClass=dnsNode)")

	def test_success(
		self,
		mocker: MockerFixture,
		f_domain_mixin: DomainViewMixin,
		admin_user: User,
		f_ldap_connector: LDAPConnector,
		f_runtime_settings: RuntimeSettingsSingleton,
		f_log_mixin: LogMixin,
		f_record_entry,
	):
		# Mock LDAPDNS
		m_ldap_dns_instance = mocker.Mock()
		m_ldap_dns_instance.dns_root = "fake_root"
		m_ldap_dns_instance.dns_zones = [
			"RootDNSServers",
			f_runtime_settings.LDAP_DOMAIN,
		]
		m_ldap_dns_instance.forest_zones = ["mock_forest_zone"]
		m_ldap_dns = mocker.patch(
			"core.views.mixins.ldap.domain.LDAPDNS",
			return_value=m_ldap_dns_instance,
		)

		# Mock Inner Functions
		m_get_ttl = mocker.Mock(return_value=180)
		m_DNS_RECORD_instance = mocker.Mock()
		m_DNS_RECORD_instance.__getTTL__ = m_get_ttl
		m_DNS_RECORD = mocker.patch(
			"core.views.mixins.ldap.domain.DNS_RECORD",
			return_value=m_DNS_RECORD_instance,
		)
		m_record_dict = {}
		m_record_to_dict = mocker.patch(
			"core.views.mixins.ldap.domain.record_to_dict",
			return_value=m_record_dict,
		)
		m_getldapattrvalue = mocker.patch(
			"core.views.mixins.ldap.domain.getldapattrvalue",
			side_effect=["mock_name", False],
		)
		m_dnsRecord = mocker.Mock()
		m_record_in_entry = getattr(
			f_record_entry, LDNS_ATTR_ENTRY_RECORD
		).value
		m_dnsRecord.values = ["mock_record"]
		f_ldap_connector.connection.entries = [f_record_entry]

		# Execution
		result = f_domain_mixin.get_zone_records(
			user=admin_user, target_zone=f_runtime_settings.LDAP_DOMAIN
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
		m_getldapattrvalue.assert_any_call(f_record_entry, "name")
		m_getldapattrvalue.assert_any_call(f_record_entry, "dNSTombstoned")
		m_get_ttl.assert_called_once()
		m_record_to_dict.assert_called_once_with(
			record=m_DNS_RECORD_instance, ts=False
		)
		f_log_mixin.log.assert_called_once_with(
			user=admin_user.id,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_DNSZ,
			log_target=f_runtime_settings.LDAP_DOMAIN,
		)
		for k in (
			"dnsZones",
			"forestZones",
			"records",
			"legacy",
		):
			assert k in result
		assert set(result["headers"]) == set(
			[
				LDNS_ATTR_ENTRY_DISPLAY_NAME,  # Custom Header, attr not in LDAP
				LOCAL_ATTR_VALUE,
				LDNS_ATTR_TTL,
				LDNS_ATTR_TYPE_NAME,
				LDNS_ATTR_SERIAL,
			]
		)
		assert result["dnsZones"] == [
			"Root DNS Servers",
			f_runtime_settings.LDAP_DOMAIN,
		]
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
			}
		)
		assert result == "mock_result"

	def test_insert_ns_a(
		self,
		mocker: MockerFixture,
		f_domain_mixin: DomainViewMixin,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		m_address = "127.0.0.1"
		f_domain_mixin.connection.result = "mock_result"
		m_ldap_record_a = mocker.Mock()
		m_ldap_record_ns = mocker.Mock()
		m_ldap_record = mocker.patch(
			"core.views.mixins.ldap.domain.LDAPRecord",
			side_effect=[m_ldap_record_a, m_ldap_record_ns],
		)
		result = f_domain_mixin.insert_nameserver_a(
			ip_address=m_address,
			target_zone=f_runtime_settings.LDAP_DOMAIN,
			ttl=180,
			serial=1,
		)

		# Assertions
		m_ldap_record.call_count == 2
		m_ldap_record.assert_any_call(
			connection=f_domain_mixin.connection,
			record_name="@",
			record_zone=f_runtime_settings.LDAP_DOMAIN,
			record_type=RecordTypes.DNS_RECORD_TYPE_A.value,
			record_main_value=m_address,
		)
		m_ldap_record_a.create.assert_called_once_with(
			values={
				"address": m_address,
				"ttl": 180,
				"serial": 1,
			}
		)
		m_ldap_record.assert_any_call(
			connection=f_domain_mixin.connection,
			record_name="ns1",
			record_zone=f_runtime_settings.LDAP_DOMAIN,
			record_type=RecordTypes.DNS_RECORD_TYPE_A.value,
			record_main_value=m_address,
		)
		m_ldap_record_ns.create.assert_called_once_with(
			values={
				"address": m_address,
				"ttl": 180,
				"serial": 1,
			}
		)
		assert result[0] == "mock_result"
		assert result[1] == "mock_result"

	def test_insert_ns_aaaa(
		self,
		mocker: MockerFixture,
		f_domain_mixin: DomainViewMixin,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		m_address = "::1"
		f_domain_mixin.connection.result = "mock_result"
		m_ldap_record_aaaa = mocker.Mock()
		m_ldap_record_ns = mocker.Mock()
		m_ldap_record = mocker.patch(
			"core.views.mixins.ldap.domain.LDAPRecord",
			side_effect=[m_ldap_record_aaaa, m_ldap_record_ns],
		)
		result = f_domain_mixin.insert_nameserver_aaaa(
			ip_address=m_address,
			target_zone=f_runtime_settings.LDAP_DOMAIN,
			ttl=180,
			serial=1,
		)

		# Assertions
		m_ldap_record.call_count == 2
		m_ldap_record.assert_any_call(
			connection=f_domain_mixin.connection,
			record_name="@",
			record_zone=f_runtime_settings.LDAP_DOMAIN,
			record_type=RecordTypes.DNS_RECORD_TYPE_AAAA.value,
			record_main_value=m_address,
		)
		m_ldap_record_aaaa.create.assert_called_once_with(
			values={
				"ipv6Address": m_address,
				"ttl": 180,
				"serial": 1,
			}
		)
		m_ldap_record.assert_any_call(
			connection=f_domain_mixin.connection,
			record_name="ns1",
			record_zone=f_runtime_settings.LDAP_DOMAIN,
			record_type=RecordTypes.DNS_RECORD_TYPE_AAAA.value,
			record_main_value=m_address,
		)
		m_ldap_record_ns.create.assert_called_once_with(
			values={
				"ipv6Address": m_address,
				"ttl": 180,
				"serial": 1,
			}
		)
		assert result[0] == "mock_result"
		assert result[1] == "mock_result"

	def test_insert_ns(
		self,
		f_domain_mixin: DomainViewMixin,
		f_runtime_settings: RuntimeSettingsSingleton,
		fc_ldap_record,
	):
		f_domain_mixin.connection.result = "mock_result"
		m_ldap_record, m_ldap_record_instance = fc_ldap_record()
		result = f_domain_mixin.insert_nameserver_ns(
			target_zone=f_runtime_settings.LDAP_DOMAIN,
			ttl=180,
			serial=1,
		)

		# Assertions
		m_ldap_record.assert_called_once_with(
			connection=f_domain_mixin.connection,
			record_name="@",
			record_zone=f_runtime_settings.LDAP_DOMAIN,
			record_type=RecordTypes.DNS_RECORD_TYPE_NS.value,
			record_main_value=f"ns1.{f_runtime_settings.LDAP_DOMAIN}.",
		)
		m_ldap_record_instance.create.assert_called_once_with(
			values={
				"nameNode": f"ns1.{f_runtime_settings.LDAP_DOMAIN}.",
				"ttl": 180,
				"serial": 1,
			}
		)
		assert result == "mock_result"


class TestInsertZone:
	@staticmethod
	def test_raises_zone_exists(
		mocker: MockerFixture,
		admin_user: User,
		f_domain_mixin: DomainViewMixin,
		f_ldap_connector: LDAPConnector,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		m_ldap_dns_instance = mocker.Mock()
		m_ldap_dns_instance.dns_zones = [f_runtime_settings.LDAP_DOMAIN]
		mocker.patch(
			"core.views.mixins.ldap.domain.LDAPDNS",
			return_value=m_ldap_dns_instance,
		)
		with pytest.raises(exc_dns.DNSZoneExists):
			f_domain_mixin.insert_zone(
				user=admin_user, target_zone=f_runtime_settings.LDAP_DOMAIN
			)

	@staticmethod
	@pytest.mark.parametrize(
		"ipv4_address, ipv6_address",
		(
			("127.0.0.1", None),
			(None, "::1"),
		),
		ids=[
			"IPv4 Zone Insertion",
			"IPv6 Zone Insertion",
		],
	)
	def test_success(
		mocker: MockerFixture,
		ipv4_address: str,
		ipv6_address: str,
		admin_user: User,
		f_ldap_connector: LDAPConnector,
		f_runtime_settings: RuntimeSettingsSingleton,
		f_domain_mixin: DomainViewMixin,
		f_log_mixin: LogMixin,
	):
		# Mock Data
		m_ldap_dns_instance = mocker.Mock()
		m_dns_root = "fake_root"
		m_forest_root = "fake_forest_root"
		m_ldap_dns_instance.dns_root = m_dns_root
		m_ldap_dns_instance.forest_root = m_forest_root
		m_ldap_dns_instance.dns_zones = ["RootDNSServers"]
		mocker.patch(
			"core.views.mixins.ldap.domain.LDAPDNS",
			return_value=m_ldap_dns_instance,
		)
		# Patch Mixin Methods
		m_create_initial_serial = mocker.patch.object(
			f_domain_mixin, "create_initial_serial", return_value=1
		)
		m_insert_soa = mocker.patch.object(
			f_domain_mixin, "insert_soa", return_value="result_soa"
		)
		m_insert_ns_a = mocker.patch.object(
			f_domain_mixin,
			"insert_nameserver_a",
			return_value=("result_a", "result_ns_a"),
		)
		m_insert_ns_aaaa = mocker.patch.object(
			f_domain_mixin,
			"insert_nameserver_aaaa",
			return_value=("result_aaaa", "result_ns_aaaa"),
		)
		m_insert_ns = mocker.patch.object(
			f_domain_mixin, "insert_nameserver_ns", return_value="result_ns"
		)
		# Mock LDAP Server IP
		m_ldap_server = mocker.Mock()
		m_ldap_server.host = ipv4_address if ipv4_address else ipv6_address
		f_ldap_connector.connection.server_pool.get_current_server.return_value = m_ldap_server

		# Execution
		result = f_domain_mixin.insert_zone(
			user=admin_user, target_zone=f_runtime_settings.LDAP_DOMAIN
		)

		# Assertions
		m_create_initial_serial.assert_called_once()
		f_ldap_connector.connection.add.call_count == 2
		f_ldap_connector.connection.add.assert_any_call(
			dn=f"DC={f_runtime_settings.LDAP_DOMAIN},{m_dns_root}",
			object_class=["dnsZone", "top"],
			attributes={"dc": f_runtime_settings.LDAP_DOMAIN},
		)
		f_ldap_connector.connection.add.assert_any_call(
			dn=f"DC=_msdcs.{f_runtime_settings.LDAP_DOMAIN},{m_forest_root}",
			object_class=["dnsZone", "top"],
			attributes={"dc": f"_msdcs.{f_runtime_settings.LDAP_DOMAIN}"},
		)
		f_ldap_connector.connection.server_pool.get_current_server.assert_called_once_with(
			f_ldap_connector.connection
		)

		# Check Record Insertions
		f_ldap_connector.cls_mock.assert_called_once_with(admin_user)
		m_insert_soa.assert_called_once_with(
			target_zone=f_runtime_settings.LDAP_DOMAIN,
			ttl=900,
			serial=1,
		)
		if ipv4_address:
			m_insert_ns_a.assert_called_once_with(
				target_zone=f_runtime_settings.LDAP_DOMAIN,
				ip_address=ipv4_address,
				ttl=900,
				serial=1,
			)
		elif ipv6_address:
			m_insert_ns_aaaa.assert_called_once_with(
				target_zone=f_runtime_settings.LDAP_DOMAIN,
				ip_address=ipv6_address,
				ttl=900,
				serial=1,
			)
		m_insert_ns.assert_called_once_with(
			target_zone=f_runtime_settings.LDAP_DOMAIN,
			ttl=3600,
			serial=1,
		)
		f_log_mixin.log.assert_called_once_with(
			user=admin_user.id,
			operation_type=LOG_ACTION_CREATE,
			log_target_class=LOG_CLASS_DNSZ,
			log_target=f_runtime_settings.LDAP_DOMAIN,
		)
		for k in (
			"soa",
			"dns",
			"forest",
		):
			assert k in result
		assert result["soa"] == "result_soa"
		assert result["ns"] == "result_ns"
		if ipv4_address:
			assert result["a"] == "result_a"
			assert result["a_ns"] == "result_ns_a"
		elif ipv6_address:
			assert result["aaaa"] == "result_aaaa"
			assert result["aaaa_ns"] == "result_ns_aaaa"


class TestDeleteZone:
	@staticmethod
	def test_raises_zone_does_not_exist(
		mocker: MockerFixture,
		f_ldap_connector: LDAPConnector,
		admin_user: User,
		f_runtime_settings: RuntimeSettingsSingleton,
		f_domain_mixin: DomainViewMixin,
	):
		# Mock Connection
		m_connection = f_ldap_connector.connection
		f_domain_mixin.connection = m_connection

		# Mock Data
		m_ldap_dns_instance = mocker.Mock()
		m_dns_root = "fake_root"
		m_forest_root = "fake_forest_root"
		m_ldap_dns_instance.dns_root = m_dns_root
		m_ldap_dns_instance.forest_root = m_forest_root
		m_ldap_dns_instance.dns_zones = ["RootDNSServers"]
		mocker.patch(
			"core.views.mixins.ldap.domain.LDAPDNS",
			return_value=m_ldap_dns_instance,
		)
		# Execute
		with pytest.raises(exc_dns.DNSZoneDoesNotExist):
			f_domain_mixin.delete_zone(
				user=admin_user, target_zone=f_runtime_settings.LDAP_DOMAIN
			)

	@staticmethod
	def test_success(
		mocker: MockerFixture,
		f_ldap_connector: LDAPConnector,
		admin_user: User,
		f_runtime_settings: RuntimeSettingsSingleton,
		f_domain_mixin: DomainViewMixin,
		f_log_mixin: LogMixin,
	):
		# Mock Connection
		m_connection = f_ldap_connector.connection
		f_domain_mixin.connection = m_connection

		# Mock Data
		m_ldap_dns_instance = mocker.Mock()
		m_dns_root = "fake_root"
		m_forest_root = "fake_forest_root"
		m_ldap_dns_instance.dns_root = m_dns_root
		m_ldap_dns_instance.forest_root = m_forest_root
		m_ldap_dns_instance.dns_zones = [
			"RootDNSServers",
			f_runtime_settings.LDAP_DOMAIN,
		]
		m_ldap_dns = mocker.patch(
			"core.views.mixins.ldap.domain.LDAPDNS",
			return_value=m_ldap_dns_instance,
		)
		# Mock Zone Records
		m_entry_1 = mocker.Mock()
		m_entry_1.entry_dn = "mock_dn_1"
		m_entry_2 = mocker.Mock()
		m_entry_2.entry_dn = "mock_dn_2"
		m_records = [m_entry_1, m_entry_2]
		m_connection.entries = m_records

		# Execute
		f_domain_mixin.delete_zone(
			user=admin_user, target_zone=f_runtime_settings.LDAP_DOMAIN
		)

		# Assertions
		f_ldap_connector.cls_mock.assert_called_once_with(admin_user)
		m_ldap_dns.assert_called_once_with(m_connection)
		m_connection.search.assert_called_once_with(
			search_base=f"DC={f_runtime_settings.LDAP_DOMAIN},{m_dns_root}",
			search_filter="(objectClass=dnsNode)",
			search_scope=ldap3_LEVEL,
			attributes=["dnsRecord", "dNSTombstoned", "name"],
		)
		m_connection.delete.call_count == len(m_records) + 2
		for mocK_record_entry in m_records:
			m_connection.delete.assert_any_call(dn=mocK_record_entry.entry_dn)
		m_connection.delete.assert_any_call(
			dn=f"DC={f_runtime_settings.LDAP_DOMAIN},{m_dns_root}"
		)
		m_connection.delete.assert_any_call(
			dn=f"DC=_msdcs.{f_runtime_settings.LDAP_DOMAIN},{m_forest_root}"
		)
		f_log_mixin.log.assert_called_once_with(
			user=admin_user.id,
			operation_type=LOG_ACTION_DELETE,
			log_target_class=LOG_CLASS_DNSZ,
			log_target=f_runtime_settings.LDAP_DOMAIN,
		)
