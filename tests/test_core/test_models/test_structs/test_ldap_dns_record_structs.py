import pytest
from core.utils.dnstool import new_record
from core.models.structs.ldap_dns_record import (
    DNS_RECORD,
    DNS_RPC_RECORD_A,
    DNS_RPC_RECORD_AAAA,
    DNS_COUNT_NAME,
    DNS_RPC_RECORD_SOA,
    record_to_dict,
    RecordTypes,
    DNS_RPC_RECORD_TS,
    DNS_RPC_RECORD_NODE_NAME,
)
from impacket.structure import Structure
import socket
import struct
from calendar import timegm
from datetime import datetime, timezone

# Source for Windows datetime
# https://github.com/jleclanche/winfiletime/blob/master/winfiletime/filetime.py
EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as filetime
HUNDREDS_OF_NS = 10000000

def from_datetime(dt: datetime) -> int:
	"""
	Converts a datetime to a Windows filetime. If the object is
	time zone-naive, it is forced to UTC before conversion.
	"""

	if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
		dt = dt.replace(tzinfo=timezone.utc)

	filetime = EPOCH_AS_FILETIME + (timegm(dt.timetuple()) * HUNDREDS_OF_NS)
	return filetime + (dt.microsecond * 10)

# Fixtures ---------------------------------------------------------------- #

@pytest.fixture
def f_dns_record_a():
    record: DNS_RECORD = new_record(
        RecordTypes.DNS_RECORD_TYPE_A.value,
        serial=1,
        ttl=180
    )
    data = DNS_RPC_RECORD_A()
    data.fromCanonical("192.168.1.1")
    record["Data"] = data
    return DNS_RECORD(record.getData())

@pytest.fixture
def f_dns_record_aaaa():
    record: DNS_RECORD = new_record(
        RecordTypes.DNS_RECORD_TYPE_AAAA.value,
        serial=1,
        ttl=180
    )
    record["Data"] = DNS_RPC_RECORD_AAAA()
    record["Data"]["ipv6Address"] = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    return DNS_RECORD(record.getData())

@pytest.fixture
def f_dns_record_cname():
    record: DNS_RECORD = new_record(
        RecordTypes.DNS_RECORD_TYPE_CNAME.value,
        serial=1,
        ttl=180
    )
    node = DNS_RPC_RECORD_NODE_NAME()
    node["nameNode"] = DNS_COUNT_NAME()
    node["nameNode"].toCountName("example.com")
    record["Data"] = node
    return DNS_RECORD(record.getData())

# Tests -------------------------------------------------------------------- #

class TestDNSRecordStructure:
    def test_dns_record_initialization(self):
        record = DNS_RECORD()
        assert isinstance(record, Structure)
        structure_fields = [field[0] for field in DNS_RECORD.structure]
        assert "DataLength" in structure_fields
        assert "Type" in structure_fields
        assert "Data" in structure_fields

class TestARecordHandling:
    def test_a_record_conversion(self, f_dns_record_a):
        result = record_to_dict(f_dns_record_a)
        assert result["typeName"] == "A"
        assert result["address"] == "192.168.1.1"

    def test_a_record_parsing(self):
        packed_ip = socket.inet_pton(socket.AF_INET, "10.0.0.1")
        record = DNS_RPC_RECORD_A(packed_ip)
        assert record.formatCanonical() == "10.0.0.1"

class TestAAAARecordHandling:
    def test_aaaa_record_conversion(self, f_dns_record_aaaa):
        result = record_to_dict(f_dns_record_aaaa)
        assert result["typeName"] == "AAAA"
        assert result["ipv6Address"] == "2001:db8::1"

    def test_aaaa_record_parsing(self):
        packed_ip = socket.inet_pton(socket.AF_INET6, "::1")
        record = DNS_RPC_RECORD_AAAA(packed_ip)
        assert record.formatCanonical() == "::1"

class TestCNAMERecordHandling:
    def test_cname_record_conversion(self, f_dns_record_cname):
        result = record_to_dict(f_dns_record_cname)
        assert result["typeName"] == "CNAME"
        assert "nameNode" in result
        assert result["nameNode"].endswith("example.com.")

class TestCountNameHandling:
    def test_count_name_conversion(self):
        count_name = DNS_COUNT_NAME()
        count_name.toCountName("sub.domain.example.com")
        assert count_name.toFqdn() == "sub.domain.example.com."

    def test_invalid_count_name_length(self):
        count_name = DNS_COUNT_NAME()
        long_string = "a" * 300
        with pytest.raises(struct.error):
            count_name.toCountName(long_string)

class TestSOARecordHandling:
    def test_soa_record_serialization(self):
        soa = DNS_RPC_RECORD_SOA()
        soa["dwSerialNo"] = 123456
        soa["namePrimaryServer"] = DNS_COUNT_NAME()
        soa["namePrimaryServer"].toCountName("ns1.example.com")
        
        assert soa["dwSerialNo"] == 123456
        assert soa["namePrimaryServer"].toFqdn() == "ns1.example.com."

class TestTSRecordHandling:
    def test_timestamp_conversion(self):
        ts = DNS_RPC_RECORD_TS()
        ts["entombedTime"] = from_datetime(datetime(1970, 1, 1))  # Jan 1, 1970 in Windows time
        result = ts.toDatetime()
        assert result.year == 1970
        assert result.month == 1
        assert result.day == 1

class TestRecordToDict:
    def test_unsupported_record_type(self, mocker):
        record: DNS_RECORD = new_record(
            RecordTypes.DNS_RECORD_TYPE_CNAME.value,
            serial=1,
            ttl=180
        )
        record["Type"] = 9999  # Unsupported type
        result = record_to_dict(record)
        assert result["typeName"] == "Unsupported"

    @pytest.mark.parametrize(
        "tombstone_value",
        (
            True,
            "True",
            ["TRUE"],
            ["True"],
            ["True", False],
        ),
    )
    def test_tombstoned_record(self, tombstone_value, f_dns_record_a):
        result = record_to_dict(f_dns_record_a, ts=tombstone_value)
        assert result["ts"] is True

    def test_multi_record_flag(self, f_dns_record_a):
        result = record_to_dict(f_dns_record_a)
        assert "multi_record" not in result  # Should be in mapping, not result
