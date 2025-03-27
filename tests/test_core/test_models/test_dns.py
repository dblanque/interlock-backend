import pytest
from core.ldap.defaults import (
	LDAP_AUTH_SEARCH_BASE,
	LDAP_DOMAIN,
	LDAP_SCHEMA_NAMING_CONTEXT,
)
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
	DNS_COUNT_NAME,
	DNS_RPC_NAME,
	DNS_RPC_RECORD_NAME_PREFERENCE,
	DNS_RPC_RECORD_A,
	DNS_RPC_RECORD_AAAA,
	DNS_RPC_RECORD_SOA,
)
from core.exceptions.dns import (
	DNSRecordDataMalformed,
	DNSCouldNotGetSOA,
	DNSCouldNotGetSerial,
)
from datetime import datetime
from pytest_mock import MockType


TODAY_DATETIME = datetime.today()
TODAY_STR = TODAY_DATETIME.strftime(DATE_FMT)

@pytest.fixture
def f_connection(mocker):
	return mocker.MagicMock()

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
def f_runtime_settings(mocker):
	m_runtime_settings = mocker.Mock()
	m_runtime_settings.LDAP_SCHEMA_NAMING_CONTEXT = LDAP_SCHEMA_NAMING_CONTEXT
	m_runtime_settings.LDAP_AUTH_SEARCH_BASE = LDAP_AUTH_SEARCH_BASE
	return mocker.patch("core.models.dns.RuntimeSettings", m_runtime_settings)

@pytest.fixture
def f_dns_root():
	return f"CN=MicrosoftDNS,CN=System,{LDAP_AUTH_SEARCH_BASE}"

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

	def test_list_dns_zones(self, mocker, f_runtime_settings):
		m_connection = mocker.MagicMock()
		mocker.patch("core.models.dns.dnstool.get_dns_zones", return_value=[LDAP_DOMAIN])
		mocker.patch.object(LDAPDNS, "list_forest_zones", return_value=None)
		ldap_dns = LDAPDNS(m_connection)
		assert ldap_dns.dnszones == [LDAP_DOMAIN]

	def test_list_forest_zones(self, mocker, f_runtime_settings):
		m_connection = mocker.MagicMock()
		mocker.patch(
			"core.models.dns.dnstool.get_dns_zones", return_value=[f"_msdcs.{LDAP_DOMAIN}"]
		)
		mocker.patch.object(LDAPDNS, "list_dns_zones", return_value=None)
		ldap_dns = LDAPDNS(m_connection)
		assert ldap_dns.forestzones == [f"_msdcs.{LDAP_DOMAIN}"]

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
	def test_get_soa_serial_raise_malformed(self, mocker):
		m_get_soa: MockType = mocker.Mock(return_value=None)
		m_mixin = LDAPRecordMixin()
		m_mixin.get_soa = m_get_soa
		m_mixin.soa = {
			"dwSerialNo": 1,
			"serial": 2
		}
		with pytest.raises(DNSRecordDataMalformed):
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
		with pytest.raises(DNSCouldNotGetSOA):
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
		]
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
		m_mixin.soa = {
			"dwSerialNo": serial,
			"serial": serial
		}
		result = m_mixin.get_soa_serial()
		m_get_soa.assert_called_once()
		assert result == expected_serial

	def test_get_serial_when_soa(self, mocker):
		m_mixin = LDAPRecordMixin()
		m_mixin.type = RecordTypes.DNS_RECORD_TYPE_SOA.value
		m_mixin.mapping = RECORD_MAPPINGS[m_mixin.type]
		assert m_mixin.get_serial(
			record_values={"dwSerialNo": 1}
		) == 1

	def test_get_serial_when_soa_raise(self):
		m_mixin = LDAPRecordMixin()
		m_mixin.type = RecordTypes.DNS_RECORD_TYPE_SOA.value
		m_mixin.mapping = RECORD_MAPPINGS[m_mixin.type]
		with pytest.raises(DNSCouldNotGetSerial):
			m_mixin.get_serial(
				record_values={"dwSerialNo": "a"}
			)

	def test_get_serial_raise(self, mocker):
		mocker.patch.object(LDAPRecordMixin, "get_soa_serial", side_effect=DNSCouldNotGetSOA)
		m_mixin = LDAPRecordMixin()
		m_mixin.type = RecordTypes.DNS_RECORD_TYPE_A.value
		m_mixin.mapping = RECORD_MAPPINGS[m_mixin.type]
		with pytest.raises(DNSCouldNotGetSerial):
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
		assert m_mixin.get_serial(
			record_values={"serial":1},
			old_serial=1
		) == 2024010101

	def test_get_serial(self, mocker):
		mocker.patch.object(LDAPRecordMixin, "get_soa_serial", return_value=3)
		m_mixin = LDAPRecordMixin()
		m_mixin.type = RecordTypes.DNS_RECORD_TYPE_A.value
		m_mixin.mapping = RECORD_MAPPINGS[m_mixin.type]
		assert m_mixin.get_serial(
			record_values={"serial": 2},
			old_serial=1
		) == 2

	def test_record_exists_in_entry_data_doesnt_exist(self):
		assert LDAPRecordMixin().record_exists_in_entry(
			main_field="field",
			main_field_val="value"
		) is False

	def test_record_exists_in_entry_data_is_none(self):
		m_mixin = LDAPRecordMixin()
		m_mixin.data = None
		assert m_mixin.record_exists_in_entry(
			main_field="field",
			main_field_val="value"
		) is False

	def test_record_exists_in_entry_len_zero(self):
		m_mixin = LDAPRecordMixin()
		m_mixin.data = []
		assert m_mixin.record_exists_in_entry(
			main_field="field",
			main_field_val="value"
		) is False

	def test_record_exists_in_entry(self):
		m_mixin = LDAPRecordMixin()
		m_mixin.name = "subdomain"
		m_mixin.type = RecordTypes.DNS_RECORD_TYPE_A.value
		m_mixin.mapping = RECORD_MAPPINGS[m_mixin.type]
		m_mixin.data = [
			{
				"name":"subdomain",
				"type": RecordTypes.DNS_RECORD_TYPE_A.value,
				"value": "abcd"
			}
		]
		assert m_mixin.record_exists_in_entry(
			main_field="value",
			main_field_val="abcd"
		) is True

	@pytest.mark.parametrize(
		"record_type, existing_record_type, expected_result",
		(
			(
				RecordTypes.DNS_RECORD_TYPE_CNAME.value,
				RecordTypes.DNS_RECORD_TYPE_CNAME.value,
				True
			),
			(
				RecordTypes.DNS_RECORD_TYPE_CNAME.value,
				RecordTypes.DNS_RECORD_TYPE_A.value,
				False
			),
			(
				RecordTypes.DNS_RECORD_TYPE_A.value,
				RecordTypes.DNS_RECORD_TYPE_A.value,
				False
			),
			(
				RecordTypes.DNS_RECORD_TYPE_SOA.value,
				RecordTypes.DNS_RECORD_TYPE_SOA.value,
				True
			),
		),
		ids=[
			"Matching CNAME records, multi_record forbidden",
			"Non-matching CNAME-A records",
			"Matching A records, multi_record allowed",
			"Matching SOA records, multi_record forbidden",
		]
	)
	def test_record_of_type_exists(self, record_type, existing_record_type, expected_result):
		m_mixin = LDAPRecordMixin()
		m_mixin.name = "subdomain"
		m_mixin.type = record_type
		m_mixin.mapping = RECORD_MAPPINGS[m_mixin.type]
		m_mixin.data = [
			{
				"name":"aa",
				"type": existing_record_type,
				"value": "abcd"
			}
		]
		assert m_mixin.record_of_type_exists() == expected_result

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
			{
				"name":"@",
				"type": RecordTypes.DNS_RECORD_TYPE_SOA.value,
				"value": "abcd"
			}
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
				"name":"subdomain",
				"type": collision_type,
				"value": "abcd",
			},
			{
				"name":"subdomain2",
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
				"name":"subdomain",
				"type": RecordTypes.DNS_RECORD_TYPE_CNAME.value,
				"value": "abcd",
			},
			{
				"name":"subdomain2",
				"type": RecordTypes.DNS_RECORD_TYPE_A.value,
				"value": "abcd",
			},
		]
		assert m_mixin.record_has_collision(raise_exc=False) is True

	@pytest.mark.parametrize(
		"record_type, collision_type",
		(
			pytest.param(
				RecordTypes.DNS_RECORD_TYPE_A.value,
				None,
				id="DNS_RECORD_TYPE_A with itself"
			),
			pytest.param(
				RecordTypes.DNS_RECORD_TYPE_CNAME.value,
				None,
				id="DNS_RECORD_TYPE_CNAME with itself"
			),
			pytest.param(
				RecordTypes.DNS_RECORD_TYPE_AAAA.value,
				None,
				id="DNS_RECORD_TYPE_AAAA with itself"
			),
			pytest.param(
				RecordTypes.DNS_RECORD_TYPE_NS.value,
				None,
				id="DNS_RECORD_TYPE_NS with itself"
			),
			pytest.param(
				RecordTypes.DNS_RECORD_TYPE_TXT.value,
				None,
				id="DNS_RECORD_TYPE_TXT with itself"
			),
			pytest.param(
				RecordTypes.DNS_RECORD_TYPE_MX.value,
				None,
				id="DNS_RECORD_TYPE_MX with itself"
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
			{
				"name":"subdomain",
				"type": collision_type,
				"value": "abcd"
			},
			{
				"name":"subdomain2",
				"type": collision_type,
				"value": "abcd"
			},
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
				"name cannot be none"
			),
			(
				{
					"rName": "subdomain",
					"rZone": None,
					"rType": RecordTypes.DNS_RECORD_TYPE_A.value,
				},
				"zone cannot be none"
			),
			(
				{
					"rName": "subdomain",
					"rZone": LDAP_DOMAIN,
					"rType": None,
				},
				"type cannot be none"
			),
			(
				{
					"rName": "subdomain",
					"rZone": LDAP_DOMAIN,
					"rType": "A",
				},
				"valid enum integer"
			),
			(
				{
					"rName": "subdomain",
					"rZone": LDAP_DOMAIN,
					"rType": RecordTypes.DNS_RECORD_TYPE_A.value,
					"zoneType":"revLookup"
				},
				"currently unsupported"
			),
		)
	)
	def test_init_raise_value_error(
			self,
			mocker,
			f_connection,
			f_runtime_settings,
			test_args,
			expected_exc,
		):
		m_record_fetch: MockType = mocker.patch.object(
			LDAPRecord, "fetch", return_value=None)
		with pytest.raises((ValueError, TypeError)) as exc_info:
			m_record = LDAPRecord(connection=f_connection, **test_args)
		assert expected_exc in exc_info.value.args[0].lower()
		m_record_fetch.assert_not_called()

	@pytest.mark.parametrize(
		"test_types, expected_cls",
		(
			(	# DNS_RPC_RECORD_NODE_NAME Cases
				(
					RecordTypes.DNS_RECORD_TYPE_NS.value,
					RecordTypes.DNS_RECORD_TYPE_CNAME.value,
					RecordTypes.DNS_RECORD_TYPE_DNAME.value,
					RecordTypes.DNS_RECORD_TYPE_PTR.value,
				),
				DNS_COUNT_NAME,
			),
			(	# DNS_RPC_RECORD_STRING Cases
				(
					RecordTypes.DNS_RECORD_TYPE_TXT.value,
					RecordTypes.DNS_RECORD_TYPE_X25.value,
					RecordTypes.DNS_RECORD_TYPE_ISDN.value,
					RecordTypes.DNS_RECORD_TYPE_LOC.value,
					RecordTypes.DNS_RECORD_TYPE_HINFO.value,
				),
				DNS_RPC_NAME,
			),
			(	# DNS_RPC_RECORD_NAME_PREFERENCE Case
				(
					RecordTypes.DNS_RECORD_TYPE_MX.value,
				),
				DNS_RPC_RECORD_NAME_PREFERENCE,
			),
			(	# A Record Case
				(
					RecordTypes.DNS_RECORD_TYPE_A.value,
				),
				DNS_RPC_RECORD_A,
			),
			(	# AAAA Record Case
				(
					RecordTypes.DNS_RECORD_TYPE_AAAA.value,
				),
				DNS_RPC_RECORD_AAAA,
			),
			(	# SOA Record Case
				(
					RecordTypes.DNS_RECORD_TYPE_SOA.value,
				),
				DNS_RPC_RECORD_SOA,
			),
		)
	)
	def test_init(
		self,
		mocker,
		f_connection,
		f_runtime_settings,
		f_dns_root,
		test_types,
		expected_cls,
	):
		expected_dn = f"DC=subdomain,DC={f_runtime_settings.LDAP_DOMAIN},{f_dns_root}"
		for test_t in test_types:
			m_record_fetch: MockType = mocker.patch.object(
				LDAPRecord, "fetch", return_value=None)
			m_record = LDAPRecord(
				connection=f_connection,
				rName="subdomain",
				rType=test_t,
				rZone=f_runtime_settings.LDAP_DOMAIN
			)
			assert m_record.record_cls == expected_cls
			assert m_record.distinguishedName == expected_dn
			m_record_fetch.assert_called_once()

			del m_record
			del m_record_fetch

	@pytest.mark.parametrize(
		"test_type",
		(
			RecordTypes.DNS_RECORD_TYPE_SIG.value,
			RecordTypes.DNS_RECORD_TYPE_KEY.value,
			RecordTypes.DNS_RECORD_TYPE_WINS.value,
		),
		ids=lambda x: RecordTypes(x).name + " raises ValueError"
	)
	def test_init_unsupported_record(
		self,
		mocker,
		f_connection,
		f_runtime_settings,
		test_type,
	):
		m_record_fetch: MockType = mocker.patch.object(
			LDAPRecord, "fetch", return_value=None)
		with pytest.raises(ValueError, match="not valid for type"):
			m_record = LDAPRecord(
				connection=f_connection,
				rName="subdomain",
				rType=test_type,
				rZone=f_runtime_settings.LDAP_DOMAIN
			)
