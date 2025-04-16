import pytest
from pytest_mock import MockType
from core.views.mixins.ldap.record import DNSRecordMixin
from core.exceptions import dns as exc_dns
from core.models.types.ldap_dns_record import RecordTypes
from core.ldap.defaults import LDAP_DOMAIN

@pytest.fixture
def f_required_values():
	return ["name", "type", "zone", "ttl"]

@pytest.fixture
def f_record_data():
	return {
		"zone": LDAP_DOMAIN,
		"ttl": 180,
	}

@pytest.fixture
def f_record_data_soa(f_record_data):
	return {
		"name": "@",
		"type": RecordTypes.DNS_RECORD_TYPE_SOA.value,
		"dwSerialNo": 2025040701,
		"dwRefresh": 900,
		"dwRetry": 7200,
		"dwExpire": 86400,
		"dwMinimumTtl": 900,
		"namePrimaryServer": f"ldap-server.{LDAP_DOMAIN}.",
		"zoneAdminEmail": f"hostmaster.{LDAP_DOMAIN}.",
	} | f_record_data

@pytest.fixture(autouse=True)
def f_log_mixin(mocker) -> MockType:
	mock = mocker.patch("core.views.mixins.ldap.record.DBLogMixin", mocker.MagicMock())
	return mock

@pytest.fixture
def f_record_mixin(mocker) -> DNSRecordMixin:
	mixin = DNSRecordMixin()
	mixin.ldap_connection = mocker.MagicMock()
	mixin.request = mocker.MagicMock()
	return mixin

class TestDNSRecordMixin:
	def test_validate_record_data_raises_no_type(self, f_record_mixin: DNSRecordMixin):
		with pytest.raises(exc_dns.DNSRecordTypeMissing):
			f_record_mixin.validate_record_data(record_data={})

	def test_validate_record_data_raises_root_zone_disallowed(self, f_record_mixin: DNSRecordMixin):
		with pytest.raises(exc_dns.DNSRootServersOnlyCLI):
			f_record_mixin.validate_record_data(record_data={
				"name": "@",
				"ttl": 180,
				"type": RecordTypes.DNS_RECORD_TYPE_A.value,
				"zone": "Root DNS Servers",
				"address":"127.0.0.1"
			})

	def test_validate_record_soa_root_only(self, f_record_data_soa, f_record_mixin: DNSRecordMixin):
		m_bad_soa = f_record_data_soa
		m_bad_soa["name"] = "subdomain"
		with pytest.raises(exc_dns.SOARecordRootOnly):
			f_record_mixin.validate_record_data(record_data=m_bad_soa)

	def test_validate_record_string_data_len_raises(
		self,
		f_record_data,
		f_record_mixin: DNSRecordMixin,
	):
		with pytest.raises(exc_dns.DNSStringDataLimit):
			f_record_mixin.validate_record_data(record_data={
				"name": "@",
				"type": RecordTypes.DNS_RECORD_TYPE_TXT.value,
				"stringData": "a"*255,
			} | f_record_data)

	def test_validate_a_record_success(
		self,
		f_record_mixin: DNSRecordMixin,
		f_record_data: dict,
		f_required_values
	):
		assert f_record_mixin.validate_record_data(
			record_data={
				"name": "@",
				"type": RecordTypes.DNS_RECORD_TYPE_A.value,
				"address": "192.168.0.1"
			} | f_record_data,
			required_values=f_required_values
		) is True

	@pytest.mark.parametrize(
		"address",
		(
			None,
			"192.168.0",
			"asd",
			False,
		),
	)
	def test_validate_a_record_error(
		self,
		address,
		f_record_mixin: DNSRecordMixin,
		f_record_data: dict,
		f_required_values
	):
		with pytest.raises(exc_dns.DNSFieldValidatorFailed):
			f_record_mixin.validate_record_data(
				record_data={
					"name": "@",
					"type": RecordTypes.DNS_RECORD_TYPE_A.value,
					"address": address
				} | f_record_data,
				required_values=f_required_values
			)

	@pytest.mark.parametrize(
		"ipv6Address",
		(
			"2001:0db8:85a3:0000:0000:8a2e:0370:7334", # Full
			"2001:db8:85a3::8a2e:370:7334", # Compressed
			"::1", # Loopback
		),
		ids=[
			"Full IPv6",
			"Compressed IPv6",
			"Loopback IPv6",
		]
	)
	def test_validate_aaaa_record_success(
		self,
		ipv6Address: str,
		f_record_mixin: DNSRecordMixin,
		f_record_data: dict,
		f_required_values
	):
		assert f_record_mixin.validate_record_data(
			record_data={
				"name": "@",
				"type": RecordTypes.DNS_RECORD_TYPE_AAAA.value,
				"ipv6Address": ipv6Address
			} | f_record_data,
			required_values=f_required_values
		) is True

	@pytest.mark.parametrize(
		"address",
		(
			None,
			False,
			"",
			"192.168.0", # Bad IPv4
			"192.168.0.1", # IPv4
			"2001::85a3::8a2e", # Compressed IPv6
		),
		ids=[
			"None",
			"False",
			"Empty String",
			"Bad IPv4",
			"IPv4",
			"Compressed IPv6",
		]
	)
	def test_validate_aaaa_record_error(
		self,
		address,
		f_record_mixin: DNSRecordMixin,
		f_record_data: dict,
		f_required_values
	):
		with pytest.raises(exc_dns.DNSFieldValidatorFailed) as e:
			f_record_mixin.validate_record_data(
				record_data={
					"name": "@",
					"type": RecordTypes.DNS_RECORD_TYPE_AAAA.value,
					"ipv6Address": address
				} | f_record_data,
				required_values=f_required_values
			)
		assert e.value.detail["field"] == "ipv6Address"
		assert e.value.detail["value"] == address

	def test_validate_name_node_record_raises_self_reference(
		self,
		f_record_mixin: DNSRecordMixin,
		f_record_data: dict,
		f_required_values
	):
		with pytest.raises(exc_dns.DNSRecordTypeConflict):
			f_record_mixin.validate_record_data(
				record_data={
					"name": "subdomain",
					"type": RecordTypes.DNS_RECORD_TYPE_CNAME.value,
					"nameNode": f"subdomain.{LDAP_DOMAIN}."
				} | f_record_data,
				required_values=f_required_values
			)

	@pytest.mark.parametrize(
		"record_type",
		(
			RecordTypes.DNS_RECORD_TYPE_DNAME.value,
			RecordTypes.DNS_RECORD_TYPE_CNAME.value,
			RecordTypes.DNS_RECORD_TYPE_NS.value,
		),
		ids=lambda x: RecordTypes(x).name
	)
	def test_validate_name_node_record_success(
		self,
		record_type: int,
		f_record_mixin: DNSRecordMixin,
		f_record_data: dict,
		f_required_values
	):
		assert f_record_mixin.validate_record_data(
			record_data={
				"name": "subdomain",
				"type": record_type,
				"nameNode": f"subdomain2.{LDAP_DOMAIN}."
			} | f_record_data,
			required_values=f_required_values
		) is True

	@pytest.mark.parametrize(
		"nameNode",
		(
			"example.com", # Non-canonical hostname
			# Other bad values
			None,
			False,
			"asdasdasd",
			"192.168.0",
			"192.168.0.1",
			b"some_bytes",
		),
	)
	def test_validate_name_node_record_error(
		self,
		nameNode,
		f_record_mixin: DNSRecordMixin,
		f_record_data: dict,
		f_required_values
	):
		with pytest.raises(exc_dns.DNSFieldValidatorFailed) as e:
			f_record_mixin.validate_record_data(
				record_data={
					"name": "subdomain",
					"type": RecordTypes.DNS_RECORD_TYPE_CNAME.value,
					"nameNode": nameNode
				} | f_record_data,
				required_values=f_required_values
			)
		assert e.value.detail["field"] == "nameNode"
		assert e.value.detail["value"] == nameNode


	def test_validate_soa_record_success(
			self,
			f_record_mixin: DNSRecordMixin,
			f_record_data_soa: dict,
			f_required_values,
		):
		assert f_record_mixin.validate_record_data(
			record_data=f_record_data_soa,
			required_values=f_required_values
		) is True
	

	@pytest.mark.parametrize(
		"field_name, field_type",
		(
			# Int fields
			(
				"dwSerialNo",
				"int",
			),
			(
				"dwRefresh",
				"int",
			),
			(
				"dwRetry",
				"int",
			),
			(
				"dwExpire",
				"int",
			),
			(
				"dwMinimumTtl",
				"int",
			),
			# Canonical Hostname Fields
			(
				"namePrimaryServer",
				"canonical"
			),
			(
				"zoneAdminEmail",
				"canonical"
			),
		),
	)
	def test_validate_soa_record_error(
		self,
		field_name,
		field_type,
		f_record_mixin: DNSRecordMixin,
		f_record_data_soa: dict,
		f_required_values
	):
		test_bad_values_int = [
			None,
			False,
			"",
			"string_should_fail",
			b"bytes_should_fail",
			["list_should_fail"],
			{"dict":"should_fail"},
		]
		test_bad_values_canonical = [
			None,
			False,
			"",
			"string_should_fail",
			b"bytes_should_fail",
			["list_should_fail"],
			{"dict":"should_fail"},
			1,
			"example.com",
		]
		test_values = test_bad_values_int if field_type == "int" else test_bad_values_canonical

		for v in test_values:
			_data = f_record_data_soa.copy()
			_data[field_name] = v
			with pytest.raises(exc_dns.DNSFieldValidatorFailed) as e:
				f_record_mixin.validate_record_data(
					record_data=_data,
					required_values=f_required_values
				)
			assert e.value.detail["field"] == field_name
			assert e.value.detail["value"] == v

	def test_validate_srv_record_success():
		pass

	def test_validate_srv_record_error():
		pass

	def test_validate_name_exchange_record_success():
		pass

	def test_validate_name_exchange_record_error():
		pass

	def test_validate_string_data_record_success():
		pass

	def test_validate_string_data_record_error():
		pass