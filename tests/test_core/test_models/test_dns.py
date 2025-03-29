import pytest
from copy import deepcopy
from core.ldap.defaults import (
	LDAP_AUTH_SEARCH_BASE,
	LDAP_DOMAIN,
	LDAP_SCHEMA_NAMING_CONTEXT,
)
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_INCREMENT, MODIFY_REPLACE, Connection
from core.models.dns import (
	LDAPDNS,
	SerialGenerator,
	DATE_FMT,
	LDAPRecordMixin,
	LDAPRecord,
	RECORD_MAPPINGS,
)
from core.models.types.ldap_dns_record import RecordTypes
from core.models.structs.ldap_dns_record import (
	DNS_RECORD,
	DNS_COUNT_NAME,
	DNS_RPC_NAME,
	DNS_RPC_RECORD_NODE_NAME,
	DNS_RPC_RECORD_STRING,
	DNS_RPC_RECORD_NAME_PREFERENCE,
	DNS_RPC_RECORD_A,
	DNS_RPC_RECORD_AAAA,
	DNS_RPC_RECORD_SOA,
	DNS_RPC_RECORD_SRV,
)
from core.exceptions import dns as exc_dns
from datetime import datetime
from pytest_mock import MockType


TODAY_DATETIME = datetime.today()
TODAY_STR = TODAY_DATETIME.strftime(DATE_FMT)


@pytest.fixture
def f_connection(mocker):
	m_connection = mocker.MagicMock()
	m_connection.add = mocker.MagicMock(return_value=None)
	m_connection.modify = mocker.MagicMock(return_value=None)
	m_connection.delete = mocker.MagicMock(return_value=None)
	m_connection.search = mocker.MagicMock(return_value=None)
	return m_connection


def get_mock_serial(serial: int):
	if len(str(serial)) >= 10:
		return serial
	return int(f"{TODAY_STR}{str(serial).rjust(2, '0')}")


@pytest.fixture
def f_today():
	return TODAY_DATETIME


@pytest.fixture
def f_today_str():
	return TODAY_STR


@pytest.fixture
def f_dns_zones():
	return [LDAP_DOMAIN]


@pytest.fixture
def f_forest_zones():
	return [f"_msdcs.{LDAP_DOMAIN}"]


@pytest.fixture
def f_runtime_settings(mocker):
	m_runtime_settings = mocker.Mock()
	m_runtime_settings.LDAP_SCHEMA_NAMING_CONTEXT = LDAP_SCHEMA_NAMING_CONTEXT
	m_runtime_settings.LDAP_AUTH_SEARCH_BASE = LDAP_AUTH_SEARCH_BASE
	return mocker.patch("core.models.dns.RuntimeSettings", m_runtime_settings)


@pytest.fixture
def f_dns_root():
	return f"CN=MicrosoftDNS,CN=System,{LDAP_AUTH_SEARCH_BASE}"


@pytest.fixture
def f_record(mocker, f_connection, f_dns_zones, f_forest_zones) -> LDAPRecord:
	def maker(record_type, record_values: dict):
		mocker.patch.object(LDAPRecord, "fetch")
		mocker.patch.object(LDAPRecord, "list_dns_zones", return_value=f_dns_zones)
		mocker.patch.object(LDAPRecord, "list_forest_zones", return_value=f_forest_zones)
		m_record = LDAPRecord(
			connection=f_connection, rName="subdomain", rZone=LDAP_DOMAIN, rType=record_type
		)
		m_record.values = record_values
		return m_record

	return maker


@pytest.fixture
def f_record_data_type_a():
	return {
		"ts": False,
		"type": RecordTypes.DNS_RECORD_TYPE_A.value,
		"typeName": "A",
		"serial": 1,
		"address": "127.0.0.1",
		"name": "@",
		"ttl": 900,
	}


@pytest.fixture
def f_record_data_type_a_subdomain():
	return {
		"ts": False,
		"type": RecordTypes.DNS_RECORD_TYPE_A.value,
		"typeName": "A",
		"serial": 1,
		"address": "127.0.0.1",
		"name": "subdomain",
		"ttl": 900,
	}


@pytest.fixture
def f_record_data_type_ns():
	return {
		"ts": False,
		"type": RecordTypes.DNS_RECORD_TYPE_NS.value,
		"typeName": "NS",
		"serial": 1,
		"nameNode": f"ldap-server.{LDAP_DOMAIN}.",
		"name": "@",
		"ttl": 900,
	}


@pytest.fixture
def f_record_data_type_soa():
	return {
		"ts": False,
		"type": RecordTypes.DNS_RECORD_TYPE_SOA.value,
		"typeName": "SOA",
		"serial": 2025032602,
		"dwSerialNo": 2025032602,
		"dwRefresh": 900,
		"dwRetry": 7200,
		"dwExpire": 86400,
		"dwMinimumTtl": 900,
		"namePrimaryServer": f"ldap-server.{LDAP_DOMAIN}.",
		"zoneAdminEmail": f"hostmaster.{LDAP_DOMAIN}.",
		"name": "@",
		"ttl": 900,
	}


@pytest.fixture
def f_record_instance_type_a(f_record, f_record_data_type_a) -> LDAPRecord:
	return f_record(RecordTypes.DNS_RECORD_TYPE_A.value, f_record_data_type_a)


@pytest.fixture
def f_record_instance_type_soa(f_record, f_record_data_type_soa) -> LDAPRecord:
	return f_record(RecordTypes.DNS_RECORD_TYPE_SOA.value, f_record_data_type_soa)


@pytest.mark.django_db
class TestLDAPDNS:
	@pytest.mark.parametrize(
		"legacy_dns, expected_dns_root",
		(
			(True, f"CN=MicrosoftDNS,CN=System,{LDAP_AUTH_SEARCH_BASE}"),
			(False, f"CN=MicrosoftDNS,DC=DomainDnsZones,{LDAP_AUTH_SEARCH_BASE}"),
		),
		ids=["Legacy LDAP DNS", "Standard LDAP DNS"],
	)
	def test_init(self, mocker, legacy_dns, expected_dns_root, f_runtime_settings):
		m_connection = mocker.MagicMock()
		f_runtime_settings.LDAP_DNS_LEGACY = legacy_dns
		m_list_dns_zones: MockType = mocker.patch.object(
			LDAPDNS, "list_dns_zones", return_value=None
		)
		m_list_forest_zones: MockType = mocker.patch.object(
			LDAPDNS, "list_forest_zones", return_value=None
		)
		ldap_dns = LDAPDNS(m_connection)

		assert ldap_dns.dnsroot == expected_dns_root
		assert ldap_dns.forestroot == f"CN=MicrosoftDNS,DC=ForestDnsZones,{LDAP_AUTH_SEARCH_BASE}"
		m_list_dns_zones.assert_called_once()
		m_list_forest_zones.assert_called_once()

	def test_list_dns_zones(self, mocker, f_runtime_settings, f_dns_zones):
		m_connection = mocker.MagicMock()
		mocker.patch("core.models.dns.dnstool.get_dns_zones", return_value=f_dns_zones)
		mocker.patch.object(LDAPDNS, "list_forest_zones", return_value=None)
		ldap_dns = LDAPDNS(m_connection)
		assert ldap_dns.dnszones == f_dns_zones

	def test_list_forest_zones(self, mocker, f_runtime_settings, f_forest_zones):
		m_connection = mocker.MagicMock()
		mocker.patch("core.models.dns.dnstool.get_dns_zones", return_value=f_forest_zones)
		mocker.patch.object(LDAPDNS, "list_dns_zones", return_value=None)
		ldap_dns = LDAPDNS(m_connection)
		assert ldap_dns.forestzones == f_forest_zones


class TestSerialGenerator:
	def test_serial_is_epoch_datetime_raise_type_error(self):
		with pytest.raises(TypeError, match="must be an int"):
			SerialGenerator.serial_as_datetime("a")

	def test_serial_is_epoch_datetime_false(self):
		assert SerialGenerator.serial_as_datetime(1) is False

	def test_serial_is_epoch_datetime(self):
		assert SerialGenerator.serial_as_datetime(2024010121) == datetime.strptime(
			"20240101", DATE_FMT
		)

	@pytest.mark.parametrize(
		"old_serial, new_serial",
		(
			(  # (int) Different day, restart serial
				2024010121,
				1,
			),
			(  # (str) Different day, restart serial
				"2024010121",
				1,
			),
			(  # (int) Same day, increase serial
				1,
				2,
			),
			(  # (int) Same day, restart serial
				99,
				1,
			),
		),
		ids=[
			"(int) Different day, restart serial",
			"(str) Different day, restart serial",
			"(int) Same day, increase serial",
			"(int) Same day, restart serial",
		],
	)
	def test_generate_epoch(self, old_serial, new_serial):
		old_serial = get_mock_serial(old_serial)
		new_serial = get_mock_serial(new_serial)
		old_serial_obj = datetime.strptime(str(old_serial)[:8], DATE_FMT)
		generated_serial = SerialGenerator.generate_epoch(old_serial, old_serial_obj)
		assert generated_serial == new_serial

	@pytest.mark.parametrize(
		"serial, serial_date_obj, expected",
		((b"2024010121", None, "of type int or str"), (20240101_01, None, "of type datetime")),
		ids=[
			"serial not int or str raises TypeError",
			"serial_date_obj not datetime raises TypeError",
		],
	)
	def test_generate_epoch_raises_type_error(self, serial, serial_date_obj, expected):
		with pytest.raises(TypeError, match=expected):
			SerialGenerator.generate_epoch(serial, serial_date_obj)


class TestLDAPRecordMixin:
	def test_get_soa_raises_exception(self, mocker):
		mocker.patch.object(LDAPRecord, "__init__", return_value=None)
		m_record = LDAPRecord()
		m_record.type = RecordTypes.DNS_RECORD_TYPE_A.value
		m_record.soa_object = mocker.Mock(side_effect=Exception)
		with pytest.raises(exc_dns.DNSCouldNotGetSOA):
			m_record.get_soa()

	def test_get_soa_object_raises_recursion_exception(self, mocker):
		mocker.patch.object(LDAPRecord, "__init__", return_value=None)
		m_record = LDAPRecord()
		m_record.type = RecordTypes.DNS_RECORD_TYPE_SOA.value
		with pytest.raises(Exception, match="SOA Recursion"):
			m_record.get_soa_object()

	def test_get_soa(
		self,
		mocker,
		f_record_instance_type_a: LDAPRecord,
		f_record_data_type_a,
		f_record_data_type_ns,
		f_record_data_type_soa,
	):
		m_soa_object = mocker.MagicMock(name="m_soa_object")
		m_soa_object.data = [
			f_record_data_type_a,
			f_record_data_type_ns,
			f_record_data_type_soa,
		]
		m_soa_object.rawEntry = {
			"raw_attributes": {
				"name": [b"@"],
				"dnsRecord": [b"record_a", b"record_ns", b"record_soa"],
				"dNSTombstoned": [],
			}
		}
		mocker.patch.object(f_record_instance_type_a, "get_soa_object", return_value=m_soa_object)

		f_record_instance_type_a.get_soa()
		assert f_record_instance_type_a.soa_bytes == b"record_soa"
		assert f_record_instance_type_a.soa == f_record_data_type_soa

	def test_get_soa_serial_raise_malformed(self, mocker):
		m_get_soa: MockType = mocker.Mock(return_value=None)
		m_mixin = LDAPRecordMixin()
		m_mixin.get_soa = m_get_soa
		m_mixin.soa = {"dwSerialNo": 1, "serial": 2}
		with pytest.raises(exc_dns.DNSRecordDataMalformed):
			m_mixin.get_soa_serial()
			m_get_soa.assert_called_once()

	def test_get_soa_raises_could_not_get(self, mocker):
		m_get_soa: MockType = mocker.Mock(return_value=None)
		m_mixin = LDAPRecordMixin()
		m_mixin.get_soa = m_get_soa
		m_mixin.soa = {
			"serial": "a",
			"dwSerialNo": "a",
		}
		with pytest.raises(exc_dns.DNSCouldNotGetSOA):
			m_mixin.get_soa_serial()
			m_get_soa.assert_called_once()

	@pytest.mark.parametrize(
		"serial, expected_serial",
		(
			(1, 2),
			(2024010101, None),
			(None, None),
		),
		ids=[
			"Non-epoch Serial (1, 2)",
			f"Epoch Serial, different days (2024010101, {get_mock_serial(1)})",
			f"Epoch Serial, same day ({get_mock_serial(1)}, {get_mock_serial(2)})",
		],
	)
	def test_get_soa_serial(self, mocker, serial, expected_serial):
		if not serial:
			serial = get_mock_serial(1)
			if not expected_serial:
				expected_serial = get_mock_serial(2)
		if not expected_serial:
			expected_serial = get_mock_serial(1)
		m_get_soa: MockType = mocker.Mock(return_value=None)
		m_mixin = LDAPRecordMixin()
		m_mixin.get_soa = m_get_soa
		m_mixin.soa = {"dwSerialNo": serial, "serial": serial}
		result = m_mixin.get_soa_serial()
		m_get_soa.assert_called_once()
		assert result == expected_serial

	def test_get_serial_when_soa(self, mocker):
		m_mixin = LDAPRecordMixin()
		m_mixin.type = RecordTypes.DNS_RECORD_TYPE_SOA.value
		m_mixin.mapping = RECORD_MAPPINGS[m_mixin.type]
		assert m_mixin.get_serial(record_values={"dwSerialNo": 1}) == 1

	def test_get_serial_when_soa_raise(self):
		m_mixin = LDAPRecordMixin()
		m_mixin.type = RecordTypes.DNS_RECORD_TYPE_SOA.value
		m_mixin.mapping = RECORD_MAPPINGS[m_mixin.type]
		with pytest.raises(exc_dns.DNSCouldNotGetSerial):
			m_mixin.get_serial(record_values={"dwSerialNo": "a"})

	def test_get_serial_raise(self, mocker):
		mocker.patch.object(
			LDAPRecordMixin, "get_soa_serial", side_effect=exc_dns.DNSCouldNotGetSOA
		)
		m_mixin = LDAPRecordMixin()
		m_mixin.type = RecordTypes.DNS_RECORD_TYPE_A.value
		m_mixin.mapping = RECORD_MAPPINGS[m_mixin.type]
		with pytest.raises(exc_dns.DNSCouldNotGetSerial):
			m_mixin.get_serial({})

	def test_get_serial_key_doesnt_exist(self, mocker):
		mocker.patch.object(LDAPRecordMixin, "get_soa_serial", return_value=2024010101)
		m_mixin = LDAPRecordMixin()
		m_mixin.type = RecordTypes.DNS_RECORD_TYPE_A.value
		m_mixin.mapping = RECORD_MAPPINGS[m_mixin.type]
		assert m_mixin.get_serial({}) == 2024010101

	def test_get_serial_old_is_same(self, mocker):
		mocker.patch.object(LDAPRecordMixin, "get_soa_serial", return_value=2024010101)
		m_mixin = LDAPRecordMixin()
		m_mixin.type = RecordTypes.DNS_RECORD_TYPE_A.value
		m_mixin.mapping = RECORD_MAPPINGS[m_mixin.type]
		assert m_mixin.get_serial(record_values={"serial": 1}, old_serial=1) == 2024010101

	def test_get_serial(self, mocker):
		mocker.patch.object(LDAPRecordMixin, "get_soa_serial", return_value=3)
		m_mixin = LDAPRecordMixin()
		m_mixin.type = RecordTypes.DNS_RECORD_TYPE_A.value
		m_mixin.mapping = RECORD_MAPPINGS[m_mixin.type]
		assert m_mixin.get_serial(record_values={"serial": 2}, old_serial=1) == 2

	def test_record_in_entry_data_doesnt_exist(self):
		assert (
			LDAPRecordMixin().record_in_entry(main_field="field", main_field_val="value")
			is False
		)

	def test_record_in_entry_data_is_none(self):
		m_mixin = LDAPRecordMixin()
		m_mixin.data = None
		assert m_mixin.record_in_entry(main_field="field", main_field_val="value") is False

	def test_record_in_entry_len_zero(self):
		m_mixin = LDAPRecordMixin()
		m_mixin.data = []
		assert m_mixin.record_in_entry(main_field="field", main_field_val="value") is False

	def test_record_in_entry(self):
		m_mixin = LDAPRecordMixin()
		m_mixin.name = "subdomain"
		m_mixin.type = RecordTypes.DNS_RECORD_TYPE_A.value
		m_mixin.mapping = RECORD_MAPPINGS[m_mixin.type]
		m_mixin.data = [
			{"name": "subdomain", "type": RecordTypes.DNS_RECORD_TYPE_A.value, "value": "abcd"}
		]
		assert m_mixin.record_in_entry(main_field="value", main_field_val="abcd") is True

	@pytest.mark.parametrize(
		"record_type, existing_record_type, expected_result",
		(
			(
				RecordTypes.DNS_RECORD_TYPE_CNAME.value,
				RecordTypes.DNS_RECORD_TYPE_CNAME.value,
				True,
			),
			(RecordTypes.DNS_RECORD_TYPE_CNAME.value, RecordTypes.DNS_RECORD_TYPE_A.value, False),
			(RecordTypes.DNS_RECORD_TYPE_A.value, RecordTypes.DNS_RECORD_TYPE_A.value, False),
			(RecordTypes.DNS_RECORD_TYPE_SOA.value, RecordTypes.DNS_RECORD_TYPE_SOA.value, True),
		),
		ids=[
			"Matching CNAME records, multi_record forbidden",
			"Non-matching CNAME-A records",
			"Matching A records, multi_record allowed",
			"Matching SOA records, multi_record forbidden",
		],
	)
	def test_record_type_in_entry(self, record_type, existing_record_type, expected_result):
		m_mixin = LDAPRecordMixin()
		m_mixin.name = "subdomain"
		m_mixin.type = record_type
		m_mixin.mapping = RECORD_MAPPINGS[m_mixin.type]
		m_mixin.data = [{"name": "aa", "type": existing_record_type, "value": "abcd"}]
		assert m_mixin.record_type_in_entry() == expected_result

	def test_record_soa_exists_data_is_none(self):
		m_mixin = LDAPRecordMixin()
		m_mixin.data = None
		assert m_mixin.record_soa_exists() is False

	def test_record_soa_exists_data_len_zero(self):
		m_mixin = LDAPRecordMixin()
		m_mixin.data = []
		assert m_mixin.record_soa_exists() is False

	def test_record_soa_exists(self):
		m_mixin = LDAPRecordMixin()
		m_mixin.name = "subdomain"
		m_mixin.type = RecordTypes.DNS_RECORD_TYPE_A.value
		m_mixin.mapping = RECORD_MAPPINGS[m_mixin.type]
		m_mixin.data = [
			{"name": "@", "type": RecordTypes.DNS_RECORD_TYPE_SOA.value, "value": "abcd"}
		]
		assert m_mixin.record_soa_exists() is True

	def test_record_has_collision_data_is_none(self):
		m_mixin = LDAPRecordMixin()
		m_mixin.data = None
		assert m_mixin.record_has_collision() is False

	def test_record_has_collision_data_len_zero(self):
		m_mixin = LDAPRecordMixin()
		m_mixin.data = []
		assert m_mixin.record_has_collision() is False

	@pytest.mark.parametrize(
		"record_type, collision_type",
		(
			pytest.param(
				RecordTypes.DNS_RECORD_TYPE_A.value,
				RecordTypes.DNS_RECORD_TYPE_CNAME.value,
				id="DNS_RECORD_TYPE_A with DNS_RECORD_TYPE_CNAME",
			),
			pytest.param(
				RecordTypes.DNS_RECORD_TYPE_CNAME.value,
				RecordTypes.DNS_RECORD_TYPE_A.value,
				id="DNS_RECORD_TYPE_CNAME with DNS_RECORD_TYPE_A",
			),
			pytest.param(
				RecordTypes.DNS_RECORD_TYPE_AAAA.value,
				RecordTypes.DNS_RECORD_TYPE_CNAME.value,
				id="DNS_RECORD_TYPE_AAAA with DNS_RECORD_TYPE_CNAME",
			),
		),
	)
	def test_record_has_collision(self, record_type, collision_type):
		if not collision_type:
			collision_type = record_type
		m_mixin = LDAPRecordMixin()
		m_mixin.name = "subdomain"
		m_mixin.type = record_type
		m_mixin.mapping = RECORD_MAPPINGS[m_mixin.type]
		m_mixin.data = [
			{
				"name": "subdomain",
				"type": collision_type,
				"value": "abcd",
			},
			{
				"name": "subdomain2",
				"type": collision_type,
				"value": "abcd",
			},
		]
		with pytest.raises(Exception, match="conflicting DNS Record"):
			m_mixin.record_has_collision()

	def test_record_has_collision_no_raise(self):
		m_mixin = LDAPRecordMixin()
		m_mixin.name = "subdomain"
		m_mixin.type = RecordTypes.DNS_RECORD_TYPE_A.value
		m_mixin.mapping = RECORD_MAPPINGS[m_mixin.type]
		m_mixin.data = [
			{
				"name": "subdomain",
				"type": RecordTypes.DNS_RECORD_TYPE_CNAME.value,
				"value": "abcd",
			},
			{
				"name": "subdomain2",
				"type": RecordTypes.DNS_RECORD_TYPE_A.value,
				"value": "abcd",
			},
		]
		assert m_mixin.record_has_collision(raise_exc=False) is True

	@pytest.mark.parametrize(
		"record_type, collision_type",
		(
			pytest.param(
				RecordTypes.DNS_RECORD_TYPE_A.value, None, id="DNS_RECORD_TYPE_A with itself"
			),
			pytest.param(
				RecordTypes.DNS_RECORD_TYPE_CNAME.value,
				None,
				id="DNS_RECORD_TYPE_CNAME with itself",
			),
			pytest.param(
				RecordTypes.DNS_RECORD_TYPE_AAAA.value, None, id="DNS_RECORD_TYPE_AAAA with itself"
			),
			pytest.param(
				RecordTypes.DNS_RECORD_TYPE_NS.value, None, id="DNS_RECORD_TYPE_NS with itself"
			),
			pytest.param(
				RecordTypes.DNS_RECORD_TYPE_TXT.value, None, id="DNS_RECORD_TYPE_TXT with itself"
			),
			pytest.param(
				RecordTypes.DNS_RECORD_TYPE_MX.value, None, id="DNS_RECORD_TYPE_MX with itself"
			),
		),
	)
	def test_record_does_not_have_collision(self, record_type, collision_type):
		if not collision_type:
			collision_type = record_type
		m_mixin = LDAPRecordMixin()
		m_mixin.name = "subdomain"
		m_mixin.type = record_type
		m_mixin.mapping = RECORD_MAPPINGS[m_mixin.type]
		m_mixin.data = [
			{"name": "subdomain", "type": collision_type, "value": "abcd"},
			{"name": "subdomain2", "type": collision_type, "value": "abcd"},
		]
		assert m_mixin.record_has_collision() is False


class TestLDAPRecord:
	@pytest.mark.parametrize(
		"test_args, expected_exc",
		(
			(
				{
					"rName": None,
					"rZone": LDAP_DOMAIN,
					"rType": RecordTypes.DNS_RECORD_TYPE_A.value,
				},
				"name cannot be none",
			),
			(
				{
					"rName": "subdomain",
					"rZone": None,
					"rType": RecordTypes.DNS_RECORD_TYPE_A.value,
				},
				"zone cannot be none",
			),
			(
				{
					"rName": "subdomain",
					"rZone": LDAP_DOMAIN,
					"rType": None,
				},
				"type cannot be none",
			),
			(
				{
					"rName": "subdomain",
					"rZone": LDAP_DOMAIN,
					"rType": "A",
				},
				"valid enum integer",
			),
			(
				{
					"rName": "subdomain",
					"rZone": LDAP_DOMAIN,
					"rType": RecordTypes.DNS_RECORD_TYPE_A.value,
					"zoneType": "revLookup",
				},
				"currently unsupported",
			),
		),
	)
	def test_init_raise_value_error(
		self,
		mocker,
		f_connection,
		f_runtime_settings,
		test_args,
		expected_exc,
	):
		m_record_fetch: MockType = mocker.patch.object(LDAPRecord, "fetch", return_value=None)
		with pytest.raises((ValueError, TypeError)) as exc_info:
			m_record = LDAPRecord(connection=f_connection, **test_args)
		assert expected_exc in exc_info.value.args[0].lower()
		m_record_fetch.assert_not_called()

	@pytest.mark.parametrize(
		"record_type, expected_cls",
		(
			# DNS_RPC_RECORD_NODE_NAME Cases
			(
				RecordTypes.DNS_RECORD_TYPE_NS,
				DNS_COUNT_NAME,
			),
			(
				RecordTypes.DNS_RECORD_TYPE_CNAME,
				DNS_COUNT_NAME,
			),
			(
				RecordTypes.DNS_RECORD_TYPE_DNAME,
				DNS_COUNT_NAME,
			),
			(
				RecordTypes.DNS_RECORD_TYPE_PTR,
				DNS_COUNT_NAME,
			),
			# DNS_RPC_RECORD_STRING Cases
			(
				RecordTypes.DNS_RECORD_TYPE_TXT,
				DNS_RPC_NAME,
			),
			(
				RecordTypes.DNS_RECORD_TYPE_X25,
				DNS_RPC_NAME,
			),
			(
				RecordTypes.DNS_RECORD_TYPE_ISDN,
				DNS_RPC_NAME,
			),
			(
				RecordTypes.DNS_RECORD_TYPE_LOC,
				DNS_RPC_NAME,
			),
			(
				RecordTypes.DNS_RECORD_TYPE_HINFO,
				DNS_RPC_NAME,
			),
			# DNS_RPC_RECORD_NAME_PREFERENCE Case
			(
				RecordTypes.DNS_RECORD_TYPE_MX,
				DNS_RPC_RECORD_NAME_PREFERENCE,
			),
			# A Record Case
			(
				RecordTypes.DNS_RECORD_TYPE_A,
				DNS_RPC_RECORD_A,
			),
			# AAAA Record Case
			(
				RecordTypes.DNS_RECORD_TYPE_AAAA,
				DNS_RPC_RECORD_AAAA,
			),
			# SOA Record Case
			(
				RecordTypes.DNS_RECORD_TYPE_SOA,
				DNS_RPC_RECORD_SOA,
			),
		),
	)
	def test_init(
		self,
		mocker,
		f_connection,
		f_runtime_settings,
		f_dns_root,
		record_type,
		expected_cls,
	):
		expected_dn = f"DC=subdomain,DC={f_runtime_settings.LDAP_DOMAIN},{f_dns_root}"
		m_record_fetch: MockType = mocker.patch.object(LDAPRecord, "fetch", return_value=None)
		m_record = LDAPRecord(
			connection=f_connection,
			rName="subdomain",
			rType=record_type.value,
			rZone=f_runtime_settings.LDAP_DOMAIN,
		)
		assert m_record.record_cls == expected_cls
		assert m_record.distinguishedName == expected_dn
		m_record_fetch.assert_called_once()

	@pytest.mark.parametrize(
		"test_type",
		(
			RecordTypes.DNS_RECORD_TYPE_SIG.value,
			RecordTypes.DNS_RECORD_TYPE_KEY.value,
			RecordTypes.DNS_RECORD_TYPE_WINS.value,
		),
		ids=lambda x: RecordTypes(x).name + " raises DNSRecordTypeUnsupported",
	)
	def test_init_unsupported_record(
		self,
		mocker,
		f_connection,
		f_runtime_settings,
		test_type,
	):
		m_record_fetch: MockType = mocker.patch.object(LDAPRecord, "fetch", return_value=None)
		with pytest.raises(exc_dns.DNSRecordTypeUnsupported):
			m_record = LDAPRecord(
				connection=f_connection,
				rName="subdomain",
				rType=test_type,
				rZone=f_runtime_settings.LDAP_DOMAIN,
			)
		m_record_fetch.assert_not_called()

	def test_init_class_not_in_def(self, mocker, f_connection, f_runtime_settings):
		mocker.patch("core.models.dns.RECORD_MAPPINGS", {RecordTypes.DNS_RECORD_TYPE_A.value: {}})
		with pytest.raises(TypeError, match="key not in"):
			LDAPRecord(
				connection=f_connection,
				rName="subdomain",
				rType=RecordTypes.DNS_RECORD_TYPE_A.value,
				rZone=f_runtime_settings.LDAP_DOMAIN,
			)

	def test_init_record_type_no_mapping(self, mocker, f_connection, f_runtime_settings):
		mocker.patch("core.models.dns.RECORD_MAPPINGS", {})
		with pytest.raises(TypeError, match="type not found in"):
			LDAPRecord(
				connection=f_connection,
				rName="subdomain",
				rType=RecordTypes.DNS_RECORD_TYPE_A.value,
				rZone=f_runtime_settings.LDAP_DOMAIN,
			)

	def test_dunder_attributes(self, mocker):
		mocker.patch.object(LDAPRecord, "__init__", return_value=None)
		m_record = LDAPRecord()
		m_record.rawEntry = "raw_entry"
		m_record.connection = "connection"
		m_record.ldap_info = "ldap_info"
		assert len(m_record.__attributes__()) == 0

	def test_dunder_print_attributes(self, mocker):
		mocker.patch.object(LDAPRecord, "__init__", return_value=None)
		m_print: MockType = mocker.patch("core.models.dns.print")
		m_record = LDAPRecord()
		m_record.rawEntry = "raw_entry"
		m_record.data = "data"
		# Should not print raw entry
		m_record.__printAttributes__()
		m_print.assert_called_once()
		# Should print raw entry and other attributes
		m_record.__printAttributes__(print_raw_data=True)
		assert m_print.call_count == 3

	def test_dunder_connection(self, mocker):
		mocker.patch.object(LDAPRecord, "__init__", return_value=None)
		m_record = LDAPRecord()
		m_record.connection = "connection"
		assert m_record.__connection__() == "connection"

	def test_dunder_fullname_root_record(self, mocker):
		mocker.patch.object(LDAPRecord, "__init__", return_value=None)
		m_record = LDAPRecord()
		m_record.name = "@"
		m_record.zone = LDAP_DOMAIN
		m_record.type = RecordTypes.DNS_RECORD_TYPE_A.value
		m_record.mapping = RECORD_MAPPINGS[m_record.type]
		assert m_record.__fullname__() == f"{LDAP_DOMAIN} (A)"

	def test_dunder_fullname_normal_record(self, mocker):
		mocker.patch.object(LDAPRecord, "__init__", return_value=None)
		m_record = LDAPRecord()
		m_record.name = "subdomain"
		m_record.zone = LDAP_DOMAIN
		m_record.type = RecordTypes.DNS_RECORD_TYPE_A.value
		m_record.mapping = RECORD_MAPPINGS[m_record.type]
		assert m_record.__fullname__() == f"subdomain.{LDAP_DOMAIN} (A)"

	def test_dunder_soa(self, mocker):
		mocker.patch.object(LDAPRecord, "__init__", return_value=None)
		m_record = LDAPRecord()
		m_record.soa = "soa"
		assert m_record.__soa__() == "soa"

	@pytest.mark.parametrize(
		"record_type, record_spec, test_field_key, test_field_value",
		(
			(
				RecordTypes.DNS_RECORD_TYPE_A,  # Type
				DNS_RPC_RECORD_A,  # Spec
				"address",  # Key
				"127.0.0.1",  # Value
			),
			(
				RecordTypes.DNS_RECORD_TYPE_AAAA,  # Type
				DNS_RPC_RECORD_AAAA,  # Spec
				"ipv6Address",  # Key
				"::1",  # Value
			),
		),
	)
	def test_make_record_bytes_rpc_a_and_aaaa(
		self,
		mocker,
		f_record,
		record_type: RecordTypes,
		record_spec,
		test_field_key: str,
		test_field_value: str,
	):
		test_values = {test_field_key: test_field_value}
		m_serial = get_mock_serial(1)
		m_record: LDAPRecord = f_record(record_type.value, test_values)
		m_data_struct = mocker.MagicMock(spec=record_spec)
		m_data_struct.fromCanonical = mocker.Mock(return_value=None)
		m_record_struct = mocker.MagicMock(spec=DNS_RECORD)
		m_record_struct.__setitem__.return_value = None
		m_record_struct.__getitem__.return_value = m_data_struct
		m_new_record: MockType = mocker.patch(
			"core.models.dns.new_record", return_value=m_record_struct
		)

		m_record.make_record_bytes(test_values, m_serial)
		m_new_record.assert_called_once_with(record_type.value, m_serial, ttl=m_record.DEFAULT_TTL)
		m_data_struct.fromCanonical.assert_called_once_with(test_field_value)

	@pytest.mark.parametrize(
		"record_type",
		(
			RecordTypes.DNS_RECORD_TYPE_NS,
			RecordTypes.DNS_RECORD_TYPE_CNAME,
			RecordTypes.DNS_RECORD_TYPE_DNAME,
			RecordTypes.DNS_RECORD_TYPE_PTR,
		),
	)
	def test_make_record_bytes_rpc_node_name(
		self,
		mocker,
		f_record,
		record_type: RecordTypes,
	):
		test_values = {"nameNode": f"subdomain2.{LDAP_DOMAIN}."}
		m_serial = get_mock_serial(1)
		m_record: LDAPRecord = f_record(record_type.value, test_values)
		m_data_struct = mocker.MagicMock(spec=DNS_RPC_RECORD_NODE_NAME)
		m_data_struct.toCountName = mocker.Mock(return_value=None)
		m_record_struct = mocker.MagicMock(spec=DNS_RECORD)
		m_record_struct.__setitem__.return_value = None
		m_record_struct.__getitem__.return_value = m_data_struct
		m_new_record: MockType = mocker.patch(
			"core.models.dns.new_record", return_value=m_record_struct
		)

		m_record.make_record_bytes(test_values, m_serial)
		m_new_record.assert_called_once_with(record_type.value, m_serial, ttl=m_record.DEFAULT_TTL)
		m_data_struct.toCountName.assert_called_once_with(test_values["nameNode"])

	@pytest.mark.parametrize(
		"record_type",
		(
			RecordTypes.DNS_RECORD_TYPE_TXT,
			RecordTypes.DNS_RECORD_TYPE_X25,
			RecordTypes.DNS_RECORD_TYPE_ISDN,
			RecordTypes.DNS_RECORD_TYPE_LOC,
			RecordTypes.DNS_RECORD_TYPE_HINFO,
		),
	)
	def test_make_record_bytes_rpc_string(
		self,
		mocker,
		f_record,
		record_type: RecordTypes,
	):
		test_values = {"stringData": f"this is a text string."}
		m_serial = get_mock_serial(1)
		m_record: LDAPRecord = f_record(record_type.value, test_values)
		m_data_struct = mocker.MagicMock(spec=DNS_RPC_RECORD_STRING)
		m_data_struct.toRPCName = mocker.Mock(return_value=None)
		m_record_struct = mocker.MagicMock(spec=DNS_RECORD)
		m_record_struct.__setitem__.return_value = None
		m_record_struct.__getitem__.return_value = m_data_struct
		m_new_record: MockType = mocker.patch(
			"core.models.dns.new_record", return_value=m_record_struct
		)

		m_record.make_record_bytes(test_values, m_serial)
		m_new_record.assert_called_once_with(record_type.value, m_serial, ttl=m_record.DEFAULT_TTL)
		m_data_struct.toRPCName.assert_called_once_with(test_values["stringData"])

	def test_make_record_bytes_rpc_name_preference(self, mocker, f_record):
		test_values = {
			"wPreference": 10,
			"nameExchange": f"mx.{LDAP_DOMAIN}.",
		}
		m_serial = get_mock_serial(1)
		m_record: LDAPRecord = f_record(RecordTypes.DNS_RECORD_TYPE_MX.value, test_values)
		m_data_struct = mocker.MagicMock(spec=DNS_RPC_RECORD_NAME_PREFERENCE)
		m_data_struct.insert_field_to_struct = mocker.Mock(return_value=None)
		m_data_struct.setField = mocker.Mock(return_value=None)
		m_data_struct.toCountName = mocker.Mock(return_value=None)
		m_record_struct = mocker.MagicMock(spec=DNS_RECORD)
		m_record_struct.__setitem__.return_value = None
		m_record_struct.__getitem__.return_value = m_data_struct
		m_new_record: MockType = mocker.patch(
			"core.models.dns.new_record", return_value=m_record_struct
		)

		m_record.make_record_bytes(test_values, m_serial)
		m_new_record.assert_called_once_with(
			RecordTypes.DNS_RECORD_TYPE_MX.value, m_serial, ttl=m_record.DEFAULT_TTL
		)
		m_data_struct.insert_field_to_struct.assert_called_once_with(
			fieldName="wPreference",
			fieldStructVal=">H",
		)
		m_data_struct.setField.assert_called_once_with(
			"wPreference",
			value=test_values["wPreference"],
		)
		m_data_struct.toCountName.assert_called_once_with(test_values["nameExchange"])

	def test_make_record_bytes_rpc_soa(self, mocker, f_record):
		test_values = {
			"dwSerialNo": 1,
			"dwRefresh": 900,
			"dwRetry": 600,
			"dwExpire": 86400,
			"dwMinimumTtl": 900,
			"namePrimaryServer": f"ns.{LDAP_DOMAIN}.",
			"zoneAdminEmail": f"hostmaster.{LDAP_DOMAIN}",
		}
		m_serial = get_mock_serial(1)
		m_record: LDAPRecord = f_record(RecordTypes.DNS_RECORD_TYPE_SOA.value, test_values)
		m_data_struct = mocker.MagicMock(spec=DNS_RPC_RECORD_SOA)
		m_data_struct.setField = mocker.Mock(return_value=None)
		m_data_struct.addCountName = mocker.Mock(return_value=None)
		m_record_struct = mocker.MagicMock(spec=DNS_RECORD)
		m_record_struct.__setitem__.return_value = None
		m_record_struct.__getitem__.return_value = m_data_struct
		m_new_record: MockType = mocker.patch(
			"core.models.dns.new_record", return_value=m_record_struct
		)

		m_record.make_record_bytes(test_values, m_serial)
		m_new_record.assert_called_once_with(
			RecordTypes.DNS_RECORD_TYPE_SOA.value, m_serial, ttl=m_record.DEFAULT_TTL
		)
		INT_FIELDS = [
			"dwSerialNo",
			"dwRefresh",
			"dwRetry",
			"dwExpire",
			"dwMinimumTtl",
		]
		STR_FIELDS = ["namePrimaryServer", "zoneAdminEmail"]
		for f in INT_FIELDS:
			m_data_struct.setField.assert_any_call(f, test_values[f])
		for f in STR_FIELDS:
			m_data_struct.addCountName.assert_any_call(test_values[f])
		assert m_data_struct.setField.call_count == len(INT_FIELDS)
		assert m_data_struct.addCountName.call_count == len(STR_FIELDS)

	def test_make_record_bytes_rpc_srv(self, mocker, f_record):
		test_values = {
			"wPriority": 0,
			"wWeight": 5,
			"wPort": 22,
			"nameTarget": f"_ssh._tcp.{LDAP_DOMAIN}.",
		}
		m_serial = get_mock_serial(1)
		m_record: LDAPRecord = f_record(RecordTypes.DNS_RECORD_TYPE_SRV.value, test_values)
		m_data_struct = mocker.MagicMock(spec=DNS_RPC_RECORD_SRV)
		m_data_struct.setField = mocker.Mock(return_value=None)
		m_data_struct.addCountName = mocker.Mock(return_value=None)
		m_record_struct = mocker.MagicMock(spec=DNS_RECORD)
		m_record_struct.__setitem__.return_value = None
		m_record_struct.__getitem__.return_value = m_data_struct
		m_new_record: MockType = mocker.patch(
			"core.models.dns.new_record", return_value=m_record_struct
		)

		m_record.make_record_bytes(test_values, m_serial)
		m_new_record.assert_called_once_with(
			RecordTypes.DNS_RECORD_TYPE_SRV.value, m_serial, ttl=m_record.DEFAULT_TTL
		)
		INT_FIELDS = [
			"wPriority",
			"wWeight",
			"wPort",
		]
		for f in INT_FIELDS:
			m_data_struct.setField.assert_any_call(f, test_values[f])
		assert m_data_struct.setField.call_count == len(INT_FIELDS)
		m_data_struct.addCountName.assert_called_once_with(test_values["nameTarget"])

	def test_make_record_bytes_raises_unsupported(self, mocker):
		mocker.patch.object(LDAPRecord, "__init__", return_value=None)
		m_record = LDAPRecord()
		m_record.name = "subdomain"
		m_record.type = RecordTypes.DNS_RECORD_TYPE_SIG.value
		m_record.mapping = RECORD_MAPPINGS[m_record.type]
		with pytest.raises(exc_dns.DNSRecordTypeUnsupported):
			m_record.make_record_bytes({}, serial=1)

	def test_create_raises_type_error(self, f_record_instance_type_a: LDAPRecord):
		with pytest.raises(TypeError, match="must be a dict"):
			f_record_instance_type_a.create("a")
		with pytest.raises(TypeError, match="must be a dict"):
			f_record_instance_type_a.create(None)

	def test_create_raises_no_serial(
		self, mocker, f_record_instance_type_a: LDAPRecord, f_record_data_type_a: dict
	):
		mocker.patch.object(f_record_instance_type_a, "get_serial", side_effect=Exception)
		with pytest.raises(exc_dns.DNSCouldNotGetSerial):
			f_record_instance_type_a.create(f_record_data_type_a)

	def test_create_raises_from_make_bytes(
		self, mocker, f_record_instance_type_a: LDAPRecord, f_record_data_type_a: dict
	):
		mocker.patch.object(f_record_instance_type_a, "get_serial", return_value=get_mock_serial(1))
		mocker.patch.object(f_record_instance_type_a, "make_record_bytes", side_effect=Exception)
		with pytest.raises(exc_dns.DNSRecordCreate):
			f_record_instance_type_a.create(f_record_data_type_a)

	def test_create_raises_from_structure(
		self,
		mocker,
		f_record_instance_type_a: LDAPRecord,
		f_record_data_type_a: dict,
	):
		m_data_structure = mocker.MagicMock()
		m_data_structure.getData.side_effect = Exception
		mocker.patch.object(f_record_instance_type_a, "get_serial", return_value=get_mock_serial(1))
		mocker.patch.object(
			f_record_instance_type_a, "make_record_bytes", return_value=m_data_structure
		)
		with pytest.raises(exc_dns.DNSRecordCreate):
			f_record_instance_type_a.create(f_record_data_type_a)

	@pytest.mark.parametrize(
		"ttl",
		(180, None),
	)
	def test_create_entry_not_exists(
		self,
		mocker,
		ttl,
		f_connection,
		f_record_instance_type_a: LDAPRecord,
		f_record_data_type_a: dict,
	):
		expected_ttl = f_record_instance_type_a.DEFAULT_TTL
		if ttl:
			expected_ttl = ttl
			f_record_data_type_a["ttl"] = ttl
		else:
			del f_record_data_type_a["ttl"]

		mocker.patch("core.models.dns.dnstool.DNS_RECORD", return_value="DNS_RECORD")
		m_record_to_dict: MockType = mocker.patch("core.models.dns.record_to_dict")
		f_record_instance_type_a.rawEntry = None
		m_serial = get_mock_serial(1)
		m_getData_result = b"record_result"
		m_data_structure = mocker.MagicMock()
		m_data_structure.getData.return_value = m_getData_result
		m_get_serial: MockType = mocker.patch.object(
			f_record_instance_type_a, "get_serial", return_value=m_serial
		)
		m_make_record_bytes: MockType = mocker.patch.object(
			f_record_instance_type_a, "make_record_bytes", return_value=m_data_structure
		)
		m_node_data = {
			"objectCategory": "CN=Dns-Node,%s" % f_record_instance_type_a.schemaNamingContext,
			"dNSTombstoned": "FALSE",
			"name": f_record_instance_type_a.name,
			"dnsRecord": [m_getData_result],
		}

		# Do Create
		f_record_instance_type_a.create(f_record_data_type_a)

		# Check fn calls
		m_record_to_dict.assert_called_once_with("DNS_RECORD", ts=False)
		m_get_serial.assert_called_once_with(record_values=f_record_data_type_a)
		m_make_record_bytes.assert_called_once_with(
			f_record_data_type_a, ttl=expected_ttl, serial=m_serial
		)
		m_data_structure.getData.assert_called_once()
		f_connection.add.assert_called_once_with(
			f_record_instance_type_a.distinguishedName,
			["top", "dnsNode"],
			m_node_data,
		)

	def test_create_entry_not_exists_add_raises_exception(
		self,
		mocker,
		f_connection,
		f_record_instance_type_a: LDAPRecord,
		f_record_data_type_a: dict,
	):
		f_connection.add.side_effect = Exception
		mocker.patch("core.models.dns.dnstool.DNS_RECORD", return_value="DNS_RECORD")
		mocker.patch("core.models.dns.record_to_dict")
		f_record_instance_type_a.rawEntry = None
		m_serial = get_mock_serial(1)
		m_getData_result = b"record_result"
		m_data_structure = mocker.MagicMock()
		m_data_structure.getData.return_value = m_getData_result
		mocker.patch.object(f_record_instance_type_a, "get_serial", return_value=m_serial)
		mocker.patch.object(
			f_record_instance_type_a, "make_record_bytes", return_value=m_data_structure
		)

		# Do Create
		with pytest.raises(Exception):
			f_record_instance_type_a.create(f_record_data_type_a)

	def test_create_entry_exists_raises_record_exists(
		self,
		mocker,
		f_record_instance_type_a: LDAPRecord,
		f_record_data_type_a: dict,
	):
		mocker.patch("core.models.dns.dnstool.DNS_RECORD", return_value="DNS_RECORD")
		mocker.patch.object(f_record_instance_type_a, "record_in_entry", return_value=True)
		f_record_instance_type_a.rawEntry = {"attributes": {}}
		m_serial = get_mock_serial(1)
		m_getData_result = b"record_result"
		m_data_structure = mocker.MagicMock()
		m_data_structure.getData.return_value = m_getData_result
		mocker.patch.object(f_record_instance_type_a, "get_serial", return_value=m_serial)
		mocker.patch.object(
			f_record_instance_type_a, "make_record_bytes", return_value=m_data_structure
		)

		# Do Create
		with pytest.raises(exc_dns.DNSRecordExistsConflict):
			f_record_instance_type_a.create(f_record_data_type_a)

	def test_create_entry_exists_raises_record_type_in_entry(
		self,
		mocker,
		f_record_instance_type_a: LDAPRecord,
		f_record_data_type_a: dict,
	):
		mocker.patch("core.models.dns.dnstool.DNS_RECORD", return_value="DNS_RECORD")
		mocker.patch("core.models.dns.record_to_dict")
		mocker.patch.object(f_record_instance_type_a, "record_in_entry", return_value=False)
		mocker.patch.object(f_record_instance_type_a, "record_type_in_entry", return_value=True)
		f_record_instance_type_a.rawEntry = {"attributes": {}}
		m_serial = get_mock_serial(1)
		m_getData_result = b"record_result"
		m_data_structure = mocker.MagicMock()
		m_data_structure.getData.return_value = m_getData_result
		mocker.patch.object(f_record_instance_type_a, "get_serial", return_value=m_serial)
		mocker.patch.object(
			f_record_instance_type_a, "make_record_bytes", return_value=m_data_structure
		)

		# Do Create
		with pytest.raises(exc_dns.DNSRecordTypeConflict):
			f_record_instance_type_a.create(f_record_data_type_a)

	def test_create_entry_exists_raises_record_of_type_soa_exists(
		self,
		mocker,
		f_record_instance_type_soa: LDAPRecord,
		f_record_data_type_soa: dict,
	):
		mocker.patch("core.models.dns.dnstool.DNS_RECORD", return_value="DNS_RECORD")
		mocker.patch("core.models.dns.record_to_dict")
		mocker.patch.object(
			f_record_instance_type_soa, "record_in_entry", return_value=False
		)
		mocker.patch.object(f_record_instance_type_soa, "record_type_in_entry", return_value=False)
		mocker.patch.object(f_record_instance_type_soa, "record_soa_exists", return_value=True)
		f_record_instance_type_soa.rawEntry = {"attributes": {}}
		m_serial = get_mock_serial(1)
		m_getData_result = b"record_result"
		m_data_structure = mocker.MagicMock()
		m_data_structure.getData.return_value = m_getData_result
		mocker.patch.object(f_record_instance_type_soa, "get_serial", return_value=m_serial)
		mocker.patch.object(
			f_record_instance_type_soa, "make_record_bytes", return_value=m_data_structure
		)

		# Do Create
		with pytest.raises(exc_dns.DNSRecordExistsConflict):
			f_record_instance_type_soa.create(f_record_data_type_soa)

	def test_create_entry_has_collision(
		self,
		mocker,
		f_record_instance_type_a: LDAPRecord,
		f_record_data_type_a: dict,
	):
		mocker.patch("core.models.dns.dnstool.DNS_RECORD", return_value="DNS_RECORD")
		mocker.patch.object(f_record_instance_type_a, "record_in_entry", return_value=False)
		mocker.patch.object(f_record_instance_type_a, "record_type_in_entry", return_value=False)
		mocker.patch.object(f_record_instance_type_a, "record_has_collision", side_effect=Exception)
		f_record_instance_type_a.rawEntry = {"attributes": {}}
		m_serial = get_mock_serial(1)
		m_getData_result = b"record_result"
		m_data_structure = mocker.MagicMock()
		m_data_structure.getData.return_value = m_getData_result
		mocker.patch.object(f_record_instance_type_a, "get_serial", return_value=m_serial)
		mocker.patch.object(
			f_record_instance_type_a, "make_record_bytes", return_value=m_data_structure
		)

		# Do Create
		with pytest.raises(exc_dns.DNSRecordTypeConflict):
			f_record_instance_type_a.create(f_record_data_type_a)

	def test_create_entry_exists(
		self,
		mocker,
		f_connection,
		f_record_instance_type_a: LDAPRecord,
		f_record_data_type_a: dict,
	):
		mocker.patch("core.models.dns.dnstool.DNS_RECORD", return_value="DNS_RECORD")
		m_record_to_dict: MockType = mocker.patch("core.models.dns.record_to_dict")
		m_record_in_entry: MockType = mocker.patch.object(
			f_record_instance_type_a, "record_in_entry", return_value=False
		)
		m_record_type_in_entry: MockType = mocker.patch.object(
			f_record_instance_type_a, "record_type_in_entry", return_value=False
		)
		f_record_instance_type_a.rawEntry = {"attributes": {}}
		m_serial = get_mock_serial(1)
		m_getData_result = b"record_result"
		m_data_structure = mocker.MagicMock()
		m_data_structure.getData.return_value = m_getData_result
		m_get_serial: MockType = mocker.patch.object(
			f_record_instance_type_a, "get_serial", return_value=m_serial
		)
		m_make_record_bytes: MockType = mocker.patch.object(
			f_record_instance_type_a, "make_record_bytes", return_value=m_data_structure
		)

		# Do Create
		f_record_instance_type_a.create(f_record_data_type_a)

		# Check fn calls
		m_get_serial.assert_called_once_with(record_values=f_record_data_type_a)
		m_make_record_bytes.assert_called_once_with(
			f_record_data_type_a, ttl=f_record_instance_type_a.DEFAULT_TTL, serial=m_serial
		)
		m_data_structure.getData.call_count == 2
		m_record_in_entry.assert_called_once_with(
			main_field="address", main_field_val=f_record_data_type_a["address"]
		)
		m_record_type_in_entry.assert_called_once()
		m_record_to_dict.assert_called_once_with("DNS_RECORD")
		f_connection.modify.assert_called_once_with(
			f_record_instance_type_a.distinguishedName,
			{"dnsRecord": [(MODIFY_ADD, m_getData_result)]},
		)

	def test_fetch_raises_foreign_zone(self, mocker, f_dns_zones):
		mocker.patch.object(LDAPRecord, "__init__", return_value=None)
		m_record = LDAPRecord()
		m_record.dnszones = f_dns_zones
		m_record.zone = "foreignzone"
		with pytest.raises(exc_dns.DNSZoneIsForeign):
			m_record.fetch()

	def test_fetch_raises_zone_in_record(self, mocker, f_dns_zones):
		mocker.patch.object(LDAPRecord, "__init__", return_value=None)
		m_record = LDAPRecord()
		m_record.name = f"subdomain.{LDAP_DOMAIN}"
		m_record.dnszones = f_dns_zones
		m_record.zone = LDAP_DOMAIN
		with pytest.raises(exc_dns.DNSZoneInRecord):
			m_record.fetch()

	def test_fetch_no_entry_on_server(self, f_connection: Connection, f_dns_zones):
		f_connection.search.return_value = []
		# Mocks
		m_record = LDAPRecord(
			connection=f_connection,
			rName="subdomain",
			rType=RecordTypes.DNS_RECORD_TYPE_A.value,
			rZone=LDAP_DOMAIN,
			auto_fetch=False
		)
		m_record.dnszones = f_dns_zones
		expected_filter = f"(&(objectClass=dnsNode)(distinguishedName={m_record.distinguishedName}))"

		# Assertion
		assert m_record.fetch() is None
		f_connection.search.assert_called_with(
			search_base=f"DC={m_record.zone},{m_record.dnsroot}",
			search_filter=expected_filter,
			attributes=["dnsRecord", "dNSTombstoned", "name"],
		)

	def test_fetch(self, mocker, f_connection: Connection, f_dns_zones, f_record_data_type_a_subdomain):
		# Mocks
		m_record_struct = mocker.patch("core.models.dns.dnstool.DNS_RECORD", return_value=mocker.Mock(spec=DNS_RECORD))
		m_record_to_dict = mocker.patch("core.models.dns.record_to_dict", return_value=f_record_data_type_a_subdomain)
		m_record = LDAPRecord(
			connection=f_connection,
			rName=f_record_data_type_a_subdomain["name"],
			rType=f_record_data_type_a_subdomain["type"],
			rZone=LDAP_DOMAIN,
			auto_fetch=False
		)
		f_connection.response = [
			{
				'raw_dn': m_record.distinguishedName.encode(),
				'dn': m_record.distinguishedName,
				'raw_attributes': {
					'name': [m_record.name.encode()],
					'dNSTombstoned': [b'FALSE'],
					'dnsRecord': [b'record_bytes']
				},
				'attributes': {
					'name': [m_record.name],
					'dNSTombstoned': ['FALSE'],
					'dnsRecord': [b'record_bytes']
				},
				'type': 'searchResEntry'
			}
		]
		m_record.dnszones = f_dns_zones
		expected_filter = f"(&(objectClass=dnsNode)(distinguishedName={m_record.distinguishedName}))"

		# Assertion
		assert m_record.fetch() == [f_record_data_type_a_subdomain]
		assert m_record.data == [f_record_data_type_a_subdomain]
		f_connection.search.assert_called_with(
			search_base=f"DC={m_record.zone},{m_record.dnsroot}",
			search_filter=expected_filter,
			attributes=["dnsRecord", "dNSTombstoned", "name"],
		)

	# def test_update(self, mocker, f_connection: Connection, f_record_data_type_a_subdomain: dict, f_dns_zones):
	# 	# Mocks
	# 	m_new_values = deepcopy(f_record_data_type_a_subdomain)
	# 	m_record = LDAPRecord(
	# 		connection=f_connection,
	# 		rName=f_record_data_type_a_subdomain["name"],
	# 		rType=f_record_data_type_a_subdomain["type"],
	# 		rZone=LDAP_DOMAIN,
	# 		auto_fetch=False
	# 	)
	# 	m_get_serial = mocker.patch(m_record, "get_serial", return_value=get_mock_serial(1))
	# 	m_make_record_bytes = mocker.patch(m_record, "make_record_bytes", return_value=b"new_record_bytes")
	# 	m_record_in_entry = mocker.patch(m_record, "record_in_entry", return_value=False)

	# 	# Assertion
	# 	m_record.rawEntry = [
	# 		{
	# 			'raw_dn': m_record.distinguishedName.encode(),
	# 			'dn': m_record.distinguishedName,
	# 			'raw_attributes': {
	# 				'name': [m_record.name.encode()],
	# 				'dNSTombstoned': [b'FALSE'],
	# 				'dnsRecord': [b'record_bytes']
	# 			},
	# 			'attributes': {
	# 				'name': [m_record.name],
	# 				'dNSTombstoned': ['FALSE'],
	# 				'dnsRecord': [b'record_bytes']
	# 			},
	# 			'type': 'searchResEntry'
	# 		}
	# 	]
	# 	m_record.data = [f_record_data_type_a_subdomain]

	# 	m_record.update(
	# 		values=m_new_values,
	# 		old_record_values=f_record_data_type_a_subdomain,
	# 		old_record_bytes=b"record_bytes",
	# 	)