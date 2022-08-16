from core.exceptions.base import BaseException

# DNS Custom Exceptions

class DNSZoneNotInRequest(BaseException):
    status_code = 400
    default_detail = 'Could not find a valid DNS Zone value'
    default_code = 'dns_zone_missing'

class DNSZoneInRecord(BaseException):
    status_code = 400
    default_detail = 'Target Record should not include the zone'
    default_code = 'dns_zone_in_record'

class DNSRecordNotInRequest(BaseException):
    status_code = 400
    default_detail = 'DNS Record is not present in request'
    default_code = 'dns_record_not_in_request'

class DNSRecordDNMissing(BaseException):
    status_code = 400
    default_detail = 'Distinguished Name is not present in Record'
    default_code = 'dns_record_dn_missing'

class DNSRecordTypeConflict(BaseException):
    status_code = 409
    default_detail = 'Requested Record Type Insertion or Update has a conflict'
    default_code = 'dns_record_type_conflict'

class DNSRecordExistsConflict(BaseException):
    status_code = 409
    default_detail = 'Requested Record Insertion or Update already exists'
    default_code = 'dns_record_exists_conflict'

class DNSRecordTypeUnsupported(BaseException):
    status_code = 400
    default_detail = 'Creating or Updating requested Record Type is not supported'
    default_code = 'dns_record_type_unsupported'

class DNSRecordDataMissing(BaseException):
    status_code = 400
    default_detail = 'A required attribute is missing in Record Operation Request'
    default_code = 'dns_record_attr_missing'

class DNSRecordTypeMissing(BaseException):
    status_code = 400
    default_detail = 'Record Type is not in Request'
    default_code = 'dns_record_type_missing'

class DNSRecordDoesNotMatch(BaseException):
    status_code = 409
    default_detail = 'Record Data does not match server-side entry'
    default_code = 'dns_record_data_does_not_match'
class DNSRecordEntryDoesNotExist(BaseException):
    status_code = 400
    default_detail = 'Record LDAP Entry does not exist'
    default_code = 'dns_record_entry_does_not_exist'
