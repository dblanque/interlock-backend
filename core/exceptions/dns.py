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
class DistinguishedNameNotInDNSRecord(BaseException):
    status_code = 400
    default_detail = 'Distinguished Name is not present in Record'
    default_code = 'dns_dn_not_in_record'