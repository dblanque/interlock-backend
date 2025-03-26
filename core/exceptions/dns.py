from core.exceptions.base import CoreException
from rest_framework import status

# DNS Custom Exceptions


class DNSZoneNotInRequest(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "Could not find a valid DNS Zone value"
	default_code = "dns_zone_missing"


class DNSZoneIsForeign(CoreException):
	status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
	default_detail = "DNS Zone is a foreign zone, not from this LDAP Server"
	default_code = "dns_zone_foreign"


class DNSZoneInRecord(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "Target Record should not include the zone"
	default_code = "dns_zone_in_record"


class DNSZoneNotDeletable(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "That Zone is critical to the system and cannot be deleted"
	default_code = "dns_zone_not_deletable"


class DNSZoneExists(CoreException):
	status_code = status.HTTP_409_CONFLICT
	default_detail = "The Zone you wish to create already exists"
	default_code = "dns_zone_exists"


class DNSZoneDoesNotExist(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "The Zone you wish to delete does not exist"
	default_code = "dns_zone_does_not_exist"


class DNSRecordCreate(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "Could not create DNS Record"
	default_code = "dns_record_create"


class DNSRecordNotInRequest(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "DNS Record is not present in request"
	default_code = "dns_record_not_in_request"


class DNSRecordDataMalformed(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "DNS Record Data is Malformed"
	default_code = "dns_record_data_malformed"


class DNSRecordDNMissing(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "Distinguished Name is not present in Record"
	default_code = "dns_record_dn_missing"


class DNSRecordTypeConflict(CoreException):
	status_code = status.HTTP_409_CONFLICT
	default_detail = "Requested Record Type Insertion or Update has a conflict"
	default_code = "dns_record_type_conflict"


class DNSRecordExistsConflict(CoreException):
	status_code = status.HTTP_409_CONFLICT
	default_detail = "Requested Record Insertion or Update already exists"
	default_code = "dns_record_exists_conflict"


class DNSRecordTypeUnsupported(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "Creating or Updating requested Record Type is not supported"
	default_code = "dns_record_type_unsupported"


class DNSRecordDataMissing(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "A required attribute is missing in Record Operation Request"
	default_code = "dns_record_attr_missing"


class DNSRecordTypeMissing(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "Record Type is not in Request"
	default_code = "dns_record_type_missing"


class DNSRecordDoesNotMatch(CoreException):
	status_code = status.HTTP_409_CONFLICT
	default_detail = "Record Data does not match server-side entry"
	default_code = "dns_record_data_does_not_match"


class DNSRecordEntryDoesNotExist(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "Record LDAP Entry does not exist"
	default_code = "dns_record_entry_does_not_exist"


class DNSCouldNotIncrementSOA(CoreException):
	status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
	default_detail = "Unable to increment Start of Authority Serial"
	default_code = "dns_soa_serial_increment"


class DNSCouldNotGetSerial(CoreException):
	status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
	default_detail = "Unable to get record Serial"
	default_code = "dns_record_serial"


class DNSCouldNotGetSOA(CoreException):
	status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
	default_detail = "Unable to get record zone SOA"
	default_code = "dns_soa_fetch"


class SOARecordRootOnly(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "A Start Of Authority Record can only be set for the root of your zone"
	default_code = "dns_soa_record_root_only"


class DNSRootServersOnlyCLI(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "Root DNS Servers may only be modified by command-line"
	default_code = "dns_root_servers_only_cli"


class DNSFieldValidatorFailed(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "A Field in the DNS Record has failed validation"
	default_code = "dns_field_validator_failed"


class DNSFieldValidatorException(CoreException):
	status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
	default_detail = "DNS Field Validator Exception"
	default_code = "dns_field_validator_exception"


class DNSStringDataLimit(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "DNS String Data cannot contain more than 255 characters"
	default_code = "dns_string_data_limit"


class DNSListEmpty(CoreException):
	status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
	default_detail = "DNS List in LDAP Response is empty, is this Legacy or Standard DNS Mode?"
	default_code = "dns_list_response_empty"
