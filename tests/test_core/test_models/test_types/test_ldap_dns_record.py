from core.models.types.ldap_dns_record import RecordTypes
from core.models.types import ldap_dns_record as ldr

def test_record_hex_values():
	for rt in RecordTypes:
		assert rt.value == int(getattr(ldr, rt.name.replace("RECORD_","")))
