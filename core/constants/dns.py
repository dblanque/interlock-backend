################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.constants.dns

from core.constants.attrs import (
	LDAP_ATTR_DN,
	LDAP_ATTR_FULL_NAME,
	LOCAL_ATTR_ID,
	LOCAL_ATTR_NAME,
)

LDNS_CLASS_DNS_NODE = "dnsNode"

# Struct Attrs
LDNS_ATTR_STRUCT_DATA_LENGTH = "DataLength"
LDNS_ATTR_STRUCT_TYPE = "Type"
LDNS_ATTR_STRUCT_VERSION = "Version"
LDNS_ATTR_STRUCT_RANK = "Rank"
LDNS_ATTR_STRUCT_FLAGS = "Flags"
LDNS_ATTR_STRUCT_SERIAL = "Serial"
LDNS_ATTR_STRUCT_TTL_SECONDS = "TtlSeconds"
LDNS_ATTR_STRUCT_RESERVED = "Reserved"
LDNS_ATTR_STRUCT_TIMESTAMP = "TimeStamp"
LDNS_ATTR_STRUCT_DATA = "Data"
LDNS_ATTR_STRUCT_NAME_LENGTH = "cchNameLength"
LDNS_ATTR_STRUCT_DNS_NAME = "dnsName"
LDNS_ATTR_STRUCT_LENGTH = "Length"
LDNS_ATTR_STRUCT_LABEL_COUNT = "LabelCount"
LDNS_ATTR_STRUCT_RAW_NAME = "RawName"
LDNS_ATTR_STRUCT_RPC_LENGTH = "wLength"
LDNS_ATTR_STRUCT_RECORD_COUNT = "wRecordCount"
LDNS_ATTR_STRUCT_RPC_FLAGS = "dwFlags"
LDNS_ATTR_STRUCT_RPC_CHILD_COUNT = "dwChildCount"
LDNS_ATTR_STRUCT_RPC_NODE_NAME = "dnsNodeName"
LDNS_ATTR_STRUCT_TYPE = "Type"
LDNS_ATTR_STRUCT_SERIAL = "Serial"
LDNS_ATTR_STRUCT_DATA = "Data"

################################################################################
################################# RECORD ATTRS #################################
################################################################################
LDNS_ATTR_ZONE = "zone"
LDNS_ATTR_SERIAL = "serial"
LDNS_ATTR_TYPE = "type"
LDNS_ATTR_TYPE_NAME = "typeName"
LDNS_ATTR_TOMBSTONED = "ts"
LDNS_ATTR_TOMBSTONE_TIME = "tstime"
LDNS_ATTR_ENTRY_DN = LDAP_ATTR_DN
LDNS_ATTR_ENTRY_NAME = LOCAL_ATTR_NAME
LDNS_ATTR_ENTRY_DISPLAY_NAME = LDAP_ATTR_FULL_NAME
LDNS_ATTR_ID = LOCAL_ATTR_ID
LDNS_ATTR_TTL = "ttl"
LDNS_ATTR_ENTRY_RECORD = "dnsRecord"
LDNS_ATTR_ENTRY_TOMBSTONED = "dNSTombstoned"

# CNAME
LDNS_ATTR_NAME_NODE = "nameNode"
# IP Address
LDNS_ATTR_IPV4_ADDRESS = "address"
LDNS_ATTR_IPV6_ADDRESS = "ipv6Address"
# SOA
LDNS_ATTR_SOA_SERIAL = "dwSerialNo"
LDNS_ATTR_SOA_REFRESH = "dwRefresh"
LDNS_ATTR_SOA_RETRY = "dwRetry"
LDNS_ATTR_SOA_EXPIRE = "dwExpire"
LDNS_ATTR_SOA_MIN_TTL = "dwMinimumTtl"
LDNS_ATTR_SOA_PRIMARY_NS = "namePrimaryServer"
LDNS_ATTR_SOA_EMAIL = "zoneAdminEmail"

# STRING
LDNS_ATTR_STRING_DATA = "stringData"

# MX
LDNS_ATTR_MX_PRIORITY = "wPreference"
LDNS_ATTR_MX_SERVER = "nameExchange"

# SRV
LDNS_ATTR_SRV_PRIORITY = "wPriority"
LDNS_ATTR_SRV_WEIGHT = "wWeight"
LDNS_ATTR_SRV_PORT = "wPort"
LDNS_ATTR_SRV_TARGET = "nameTarget"

# SIG DNS
LDNS_ATTR_SIG_TYPE_COVERED = "wTypeCovered"
LDNS_ATTR_SIG_ALGORITHM = "chAlgorithm"
LDNS_ATTR_SIG_LABEL_COUNT = "chLabelCount"
LDNS_ATTR_SIG_ORIGINAL_TTL = "dwOriginalTtl"
LDNS_ATTR_SIG_SIG_EXPIRATION = "dwSigExpiration"
LDNS_ATTR_SIG_SIG_INCEPTION = "dwSigInception"
LDNS_ATTR_SIG_KEY_TAG = "wKeyTag"
LDNS_ATTR_SIG_NAME_SIGNER = "nameSigner"
LDNS_ATTR_SIG_SIGNATURE_INFO = "SignatureInfo"

# TOMBSTONE
LDNS_ATTR_TS_ENTOMBED_AT = "entombedTime"
