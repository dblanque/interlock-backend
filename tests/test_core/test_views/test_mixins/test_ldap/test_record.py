import pytest
from pytest_mock import MockType
from core.views.mixins.ldap.record import DNSRecordMixin
from core.exceptions import dns as exc_dns
from core.models.types.ldap_dns_record import RecordTypes
from core.models.structs.ldap_dns_record import RECORD_MAPPINGS
from core.ldap.defaults import LDAP_DOMAIN


@pytest.fixture
def f_required_values():
	return ["name", "type", "zone", "ttl"]

@pytest.fixture
def fields_for_record_type(f_required_values) -> tuple:
	def maker(record_type: RecordTypes):
		return tuple(set(f_required_values + RECORD_MAPPINGS[record_type]["fields"]))
	return maker

@pytest.fixture
def f_bad_int_values():
	return [
		None,
		False,
		"",
		"string_should_fail",
		b"bytes_should_fail",
		["list_should_fail"],
		{"dict":"should_fail"},
	]

@pytest.fixture
def f_bad_canonical_values():
	return [
		None,
		False,
		"",
		"string_should_fail",
		b"bytes_should_fail",
		["list_should_fail"],
		{"dict":"should_fail"},
		1,
		"example.com",
		"_srv.example.com",
	]

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

@pytest.fixture
def f_record_data_srv(f_record_data):
	return {
		"name": "@",
		"type": RecordTypes.DNS_RECORD_TYPE_SRV.value,
		"wPriority": 0,
		"wWeight": 5,
		"wPort": 22,
		"nameTarget": f"_ssh._tcp.{LDAP_DOMAIN}.",
	} | f_record_data

@pytest.fixture
def f_record_data_mx(f_record_data):
	return {
		"name": "@",
		"type": RecordTypes.DNS_RECORD_TYPE_MX.value,
		"wPreference": 10,
		"nameExchange": f"mx.{LDAP_DOMAIN}.",
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
	@pytest.mark.parametrize(
		"required_keys",
		(
			# list
			["key1", "key2",],
			# tuple
			("key1", "key2",),
		),
		ids=lambda x: "required_keys as " + type(x).__name__
	)
	def test_record_data_keys_are_valid(self, required_keys: list|tuple, f_record_mixin: DNSRecordMixin):
		assert f_record_mixin.record_data_keys_are_valid(
			record_data={
				"key1":"value1",
				"key2":"value2",
			},
			required_keys=required_keys
		) is True

	@pytest.mark.parametrize(
		"bad_required_keys",
		(
			False,
			None,
			{"some":"dict"},
			b"some_bytes",
		),
	)
	def test_record_data_keys_are_valid_raises_type_error(self, bad_required_keys, f_record_mixin: DNSRecordMixin):
		with pytest.raises(TypeError, match="required_keys must be of type"):
			f_record_mixin.record_data_keys_are_valid(
				record_data={"some":"dict"},
				required_keys=bad_required_keys
			)

	def test_record_data_keys_are_valid_raises_data_missing(self, f_record_mixin: DNSRecordMixin):
		with pytest.raises(exc_dns.DNSRecordDataMissing):
			f_record_mixin.record_data_keys_are_valid(
				record_data={
					"key1":"value1",
					"key2":"value2",
				},
				required_keys=["key1", "key2", "key3"],
				raise_exception=True
			)

	def test_record_data_keys_are_valid_false_on_data_missing(self, f_record_mixin: DNSRecordMixin):
		f_record_mixin.record_data_keys_are_valid(
			record_data={
				"key1":"value1",
				"key2":"value2",
			},
			required_keys=["key1", "key2", "key3"]
		) is False

	def test_record_data_keys_are_valid_raises_malformed(self, f_record_mixin: DNSRecordMixin):
		with pytest.raises(exc_dns.DNSRecordDataMalformed):
			f_record_mixin.record_data_keys_are_valid(
				record_data={
					"key1":"value1",
					"key2":"value2",
					"key3":"value3",
				},
				required_keys=["key1", "key2"],
				raise_exception=True
			)

	def test_record_data_keys_are_valid_returns_false(self, f_record_mixin: DNSRecordMixin):
		f_record_mixin.record_data_keys_are_valid(
			record_data={
				"key1":"value1",
				"key2":"value2",
				"key3":"value3",
			},
			required_keys=["key1", "key2"],
		) is False

	def test_validate_record_data_raises_unsupported(
		self,
		f_record_mixin: DNSRecordMixin,
	):
		with pytest.raises(exc_dns.DNSRecordTypeUnsupported):
			f_record_mixin.validate_record_data(record_data={"type":91237})

	def test_validate_record_data_raises_bad_required_values(
		self,
		f_record_mixin: DNSRecordMixin,
	):
		with pytest.raises(TypeError, match="required_values must be a list or tuple"):
			f_record_mixin.validate_record_data(
				record_data={"type":RecordTypes.DNS_RECORD_TYPE_A.value},
				add_required_keys=False
			)

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
		mocker,
		f_record_mixin: DNSRecordMixin,
		f_record_data: dict,
		fields_for_record_type,
	):
		m_record_data = f_record_data | {
			"name": "@",
			"type": RecordTypes.DNS_RECORD_TYPE_A.value,
			"address": "192.168.0.1"
		}
		m_keys_validator: MockType = mocker.patch.object(
			f_record_mixin, "record_data_keys_are_valid", return_value=True)
		assert f_record_mixin.validate_record_data(
			record_data=m_record_data,
			add_required_keys=["address"]
		) is True
		m_keys_validator.assert_called_once_with(
			record_data=m_record_data,
			required_keys=fields_for_record_type(RecordTypes.DNS_RECORD_TYPE_A.value),
			raise_exception=True,
		)

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
	):
		with pytest.raises(exc_dns.DNSFieldValidatorFailed):
			f_record_mixin.validate_record_data(
				record_data=f_record_data | {
					"name": "@",
					"type": RecordTypes.DNS_RECORD_TYPE_A.value,
					"address": address
				}
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
		mocker,
		ipv6Address: str,
		f_record_mixin: DNSRecordMixin,
		f_record_data: dict,
		fields_for_record_type,
	):
		m_record_data = f_record_data | {
			"name": "@",
			"type": RecordTypes.DNS_RECORD_TYPE_AAAA.value,
			"ipv6Address": ipv6Address
		}
		m_keys_validator: MockType = mocker.patch.object(
			f_record_mixin, "record_data_keys_are_valid", return_value=True)
		assert f_record_mixin.validate_record_data(
			record_data=m_record_data,
		) is True
		m_keys_validator.assert_called_once_with(
			record_data=m_record_data,
			required_keys=fields_for_record_type(RecordTypes.DNS_RECORD_TYPE_AAAA.value),
			raise_exception=True,
		)

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
	):
		with pytest.raises(exc_dns.DNSFieldValidatorFailed) as e:
			f_record_mixin.validate_record_data(
				record_data={
					"name": "@",
					"type": RecordTypes.DNS_RECORD_TYPE_AAAA.value,
					"ipv6Address": address
				} | f_record_data,
			)
		assert e.value.detail["field"] == "ipv6Address"
		assert e.value.detail["value"] == address

	def test_validate_name_node_record_raises_self_reference(
		self,
		f_record_mixin: DNSRecordMixin,
		f_record_data: dict,
	):
		with pytest.raises(exc_dns.DNSRecordTypeConflict):
			f_record_mixin.validate_record_data(
				record_data={
					"name": "subdomain",
					"type": RecordTypes.DNS_RECORD_TYPE_CNAME.value,
					"nameNode": f"subdomain.{LDAP_DOMAIN}."
				} | f_record_data
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
		mocker,
		record_type: int,
		f_record_mixin: DNSRecordMixin,
		f_record_data: dict,
		fields_for_record_type
	):
		m_record_data = f_record_data | {
			"name": "subdomain",
			"type": record_type,
			"nameNode": f"subdomain2.{LDAP_DOMAIN}."
		}
		m_keys_validator: MockType = mocker.patch.object(
			f_record_mixin, "record_data_keys_are_valid", return_value=True)
		assert f_record_mixin.validate_record_data(
			record_data=m_record_data
		) is True
		m_keys_validator.assert_called_once_with(
			record_data=m_record_data,
			required_keys=fields_for_record_type(record_type),
			raise_exception=True,
		)

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
	):
		with pytest.raises(exc_dns.DNSFieldValidatorFailed) as e:
			f_record_mixin.validate_record_data(
				record_data={
					"name": "subdomain",
					"type": RecordTypes.DNS_RECORD_TYPE_CNAME.value,
					"nameNode": nameNode
				} | f_record_data
			)
		assert e.value.detail["field"] == "nameNode"
		assert e.value.detail["value"] == nameNode


	def test_validate_soa_record_success(
			self,
			mocker,
			f_record_mixin: DNSRecordMixin,
			f_record_data_soa: dict,
			fields_for_record_type,
		):
		m_keys_validator: MockType = mocker.patch.object(
			f_record_mixin, "record_data_keys_are_valid", return_value=True)
		assert f_record_mixin.validate_record_data(record_data=f_record_data_soa) is True
		m_keys_validator.assert_called_once_with(
			record_data=f_record_data_soa,
			required_keys=fields_for_record_type(RecordTypes.DNS_RECORD_TYPE_SOA.value),
			raise_exception=True,
		)
	

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
		f_bad_int_values,
		f_bad_canonical_values,
	):
		test_values = f_bad_int_values if field_type == "int" else f_bad_canonical_values

		for v in test_values:
			_data = f_record_data_soa.copy()
			_data[field_name] = v
			with pytest.raises(exc_dns.DNSFieldValidatorFailed) as e:
				f_record_mixin.validate_record_data(record_data=_data)
			assert e.value.detail["field"] == field_name
			assert e.value.detail["value"] == v

	def test_validate_srv_record_success(
		self,
		mocker,
		f_record_data_srv,
		f_record_mixin: DNSRecordMixin,
		fields_for_record_type,
	):
		m_keys_validator: MockType = mocker.patch.object(
			f_record_mixin, "record_data_keys_are_valid", return_value=True)
		assert f_record_mixin.validate_record_data(record_data=f_record_data_srv) is True
		m_keys_validator.assert_called_once_with(
			record_data=f_record_data_srv,
			required_keys=fields_for_record_type(RecordTypes.DNS_RECORD_TYPE_SRV.value),
			raise_exception=True,
		)

	@pytest.mark.parametrize(
		"field_name, field_type",
		(
			# Int fields
			(
				"wPriority",
				"int",
			),
			(
				"wWeight",
				"int",
			),
			(
				"wPort",
				"int",
			),
			# srv field
			(
				"nameTarget",
				"srv",
			),
		),
	)
	def test_validate_srv_record_error(
		self,
		field_name,
		field_type,
		f_record_data_srv: dict,
		f_record_mixin: DNSRecordMixin,
		f_bad_int_values,
		f_bad_canonical_values,
	):
		test_values = f_bad_int_values if field_type == "int" else f_bad_canonical_values

		for v in test_values:
			_data = f_record_data_srv.copy()
			_data[field_name] = v
			with pytest.raises(exc_dns.DNSFieldValidatorFailed) as e:
				f_record_mixin.validate_record_data(record_data=_data)
			assert e.value.detail["field"] == field_name
			assert e.value.detail["value"] == v

	def test_validate_name_exchange_record_success(
		self,
		f_record_data_mx: dict,
		f_record_mixin: DNSRecordMixin,
	):
		assert f_record_mixin.validate_record_data(record_data=f_record_data_mx) is True
		
	@pytest.mark.parametrize(
		"field_name",
		(
			"wPreference",
			"nameExchange",
		),
	)
	def test_validate_name_exchange_record_error(
		self,
		field_name,
		f_record_mixin: DNSRecordMixin,
		f_bad_int_values,
		f_bad_canonical_values,
		f_record_data_mx: dict,
	):
		if field_name == "wPreference":
			test_values = f_bad_int_values
		else:
			test_values = f_bad_canonical_values

		for v in test_values:
			_data = f_record_data_mx.copy()
			_data[field_name] = v
			with pytest.raises(exc_dns.DNSFieldValidatorFailed) as e:
				f_record_mixin.validate_record_data(record_data=_data)
			assert e.value.detail["field"] == field_name
			assert e.value.detail["value"] == v

	@pytest.mark.parametrize(
		"record_type",
		(
			RecordTypes.DNS_RECORD_TYPE_TXT.value,
			RecordTypes.DNS_RECORD_TYPE_X25.value,
			RecordTypes.DNS_RECORD_TYPE_ISDN.value,
			RecordTypes.DNS_RECORD_TYPE_LOC.value,
			RecordTypes.DNS_RECORD_TYPE_HINFO.value,
		),
		ids=lambda x: RecordTypes(x).name
	)
	def test_validate_string_data_record_success(
		self,
		mocker,
		record_type: RecordTypes,
		f_record_mixin: DNSRecordMixin,
		f_record_data: dict,
		fields_for_record_type,
	):
		m_record_data = f_record_data | {
			"name": f"_some-entry.{LDAP_DOMAIN}",
			"type": record_type,
			"stringData": "Text Record Data -"
		}
		m_keys_validator: MockType = mocker.patch.object(
			f_record_mixin, "record_data_keys_are_valid", return_value=True)
		assert f_record_mixin.validate_record_data(
			record_data=m_record_data
		) is True
		m_keys_validator.assert_called_once_with(
			record_data=m_record_data,
			required_keys=fields_for_record_type(record_type),
			raise_exception=True,
		)

	@pytest.mark.parametrize(
		"bad_str_value",
		(
			None,
			False,
			b"some_bytes",
			1,
			["list"],
			{"set"},
			{"some":"dict"},
		),
	)
	def test_validate_string_data_record_error(
		self,
		bad_str_value,
		f_record_mixin: DNSRecordMixin,
		f_record_data: dict,
	):
		f_record_data = f_record_data | {
			"name": f"_some-entry.{LDAP_DOMAIN}",
			"type": RecordTypes.DNS_RECORD_TYPE_TXT.value,
			"stringData": bad_str_value,
		}
		with pytest.raises(exc_dns.DNSFieldValidatorFailed) as e:
			f_record_mixin.validate_record_data(record_data=f_record_data)
		assert e.value.detail["field"] == "stringData"
		assert e.value.detail["value"] == bad_str_value

	@pytest.mark.parametrize(
		"field_name, field_value",
		(
			("serial", 1),
			("serial", 2025041601),
			("address", "192.168.0.1"),
			("address", "10.0.0.1"),
			("ipv6Address", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"), # Full
			("ipv6Address", "2001:db8:85a3::8a2e:370:7334"), # Compressed
			("ipv6Address", "::1"), # Loopback
			("nameNode", f"subdomain.{LDAP_DOMAIN}."),
			("nameNode", f"{LDAP_DOMAIN}."),
			("nameNode", f"_srv.{LDAP_DOMAIN}."),
			("nameNode", f"_acme-challenge.{LDAP_DOMAIN}."),
			("dwSerialNo", 1),
			("dwSerialNo", 2025041601),
			("dwRefresh",  900),
			("dwRetry",  7200),
			("dwExpire", 86400),
			("dwMinimumTtl", 900),
			("namePrimaryServer", f"dns.{LDAP_DOMAIN}."),
			("zoneAdminEmail", f"hostmaster.{LDAP_DOMAIN}."),
			("stringData", "Some TXT String Data. @!230()"),
			("wPreference", 10),
			("nameExchange", f"mx.{LDAP_DOMAIN}."),
			("wPriority", 10),
			("wWeight", 10),
			("wPort", 22),
			("nameTarget", f"service.{LDAP_DOMAIN}."),
		),
		ids=[
			"Non-epoch Serial",
			"Epoch Serial",
			"IPv4 Class C Private",
			"IPv4 Class A Private",
			"Full IPv6 Address",
			"Compressed IPv6 Address",
			"Loopback IPv6 Address",
			"Standard Canonical Subdomain Hostname",
			"Standard Canonical Hostname",
			"Standard Canonical with Underscore",
			"Standard Canonical with Underscore and Hyphen",
			"Non-epoch dwSerial",
			"Epoch dwSerial",
			"SOA Refresh",
			"SOA Retry",
			"SOA Expire",
			"SOA Minimum TTL",
			"SOA Name Server",
			"SOA Hostmaster Email",
			"TXT-like String Data",
			"MX Preference",
			"MX Server",
			"SRV Priority",
			"SRV Weight",
			"SRV Port",
			"SRV Target",
		]
	)
	def test_validate_field(
		self,
		field_name,
		field_value,
		f_record_mixin: DNSRecordMixin,
	):
		assert f_record_mixin.validate_field(
			field_name=field_name,
			field_value=field_value,
			raise_exception=False
		) is True

	@pytest.mark.parametrize(
		"test_validators",
		(
			("some_validator",),
			["some_validator",],
			{"some_validator",},
		),
		ids=lambda x: type(x).__name__ + " raises recursion exception"
	)
	def test_validate_field_raises_recursion_exception(
		self,
		test_validators,
		f_record_mixin: DNSRecordMixin,
	):
		with pytest.raises(ValueError, match="recursion"):
			f_record_mixin.validate_field(
				field_name="some_field",
				field_value="some_value",
				raise_exception=False,
				_validator=test_validators
			)

	def test_validate_field_raises_on_not_str_or_callable(
		self,
		f_record_mixin: DNSRecordMixin,
	):
		with pytest.raises(TypeError, match="must be of type"):
			f_record_mixin.validate_field(
				field_name="some_field",
				field_value="some_value",
				_validator=b"bad_value"
			)

	def test_validate_field_fetching_func_from_str(
		self,
		mocker,
		f_record_mixin: DNSRecordMixin,
	):
		mocker.patch("core.views.mixins.ldap.record.DNS_FIELD_VALIDATORS", {
			"address":"ipv4_validator"
		})
		assert f_record_mixin.validate_field(
			field_name="address",
			field_value="192.168.0.1"
		) is True
		assert f_record_mixin.validate_field(
			field_name="address",
			field_value="192.168.0",
			raise_exception=False
		) is False
