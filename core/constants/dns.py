################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.constants.dns
# Contains LDAP DNS Related Constants

# ---------------------------------- IMPORTS -----------------------------------#
from core.constants.attrs import (
	LDAP_ATTR_DN,
	LDAP_ATTR_FULL_NAME,
	LOCAL_ATTR_ID,
	LOCAL_ATTR_NAME,
)
################################################################################

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

# DNSSEC
LDNS_ATTR_DNSSEC_FLAGS = "dnssecFlags"
LDNS_ATTR_DNSSEC_KEY_TAG = "wKeyTag"
LDNS_ATTR_DNSSEC_ALGORITHM = "chAlgorithm"
LDNS_ATTR_DNSSEC_PROTOCOL = "chProtocol"
LDNS_ATTR_DNSSEC_PUBLIC_KEY = "bKey"
LDNS_ATTR_DNSSEC_SIGNATURE = "signature"
LDNS_ATTR_DNSSEC_SIGNER_NAME = "nameSigner"
LDNS_ATTR_DNSSEC_ITERATIONS = "iterations"
LDNS_ATTR_DNSSEC_SALT = "salt"

LDNS_ATTR_DNSSEC_TYPE_COVERED = "wTypeCovered"
LDNS_ATTR_DNSSEC_LABELS = "chLabelCount"
LDNS_ATTR_DNSSEC_ORIGINAL_TTL = "dwOriginalTtl"
LDNS_ATTR_DNSSEC_SIG_EXPIRATION = "dwSigExpiration"
LDNS_ATTR_DNSSEC_SIG_INCEPTION = "dwSigInception"

# DNS Record Flags (dwFlags field in DNS_RECORD structure)
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/ac793981-1c60-43b8-be59-cdbb5c4ecb8a
# DNS RPC Record Flags Docs
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f448341f-512d-414a-aaa3-e303d592fcd2
# DNS Constants
# https://learn.microsoft.com/en-us/windows/win32/DNS/dns-constants
# The record came from the cache.
RANK_CACHE_BIT = 0x00000001
# The record is a preconfigured root hint.
RANK_ROOT_HINT = 0x00000008
# This value is not used.
RANK_OUTSIDE_GLUE = 0x00000020
# The record was cached from the additional section of a non-authoritative response.
RANK_CACHE_NA_ADDITIONAL = 0x00000031
# The record was cached from the authority section of a non-authoritative response.
RANK_CACHE_NA_AUTHORITY = 0x00000041
# The record was cached from the additional section of an authoritative response.
RANK_CACHE_A_ADDITIONAL = 0x00000051
# The record was cached from the answer section of a non-authoritative response.
RANK_CACHE_NA_ANSWER = 0x00000061
# The record was cached from the authority section of an authoritative response.
RANK_CACHE_A_AUTHORITY = 0x00000071
# The record is a glue record in an authoritative zone.
RANK_GLUE = 0x00000080
# The record is a delegation  (type NS) record in an authoritative zone.
RANK_NS_GLUE = 0x00000082
# The record was cached from the answer section of an authoritative response.
RANK_CACHE_A_ANSWER = 0x000000C1
# The record comes from an authoritative zone.
RANK_ZONE = 0x000000F0
# The record is at the root of a zone (not necessarily a zone hosted by this server; the record could have come from the cache).
DNS_RPC_FLAG_ZONE_ROOT = 0x40000000
# The record is at the root of a zone that is locally hosted on this server.
DNS_RPC_FLAG_AUTH_ZONE_ROOT = 0x20000000
# The record came from the cache.
DNS_RPC_FLAG_CACHE_DATA = 0x80000000
# The record SHOULD be treated as a resource record of unknown type ([RFC3597] section 2) by the DNS server.
DNS_RPC_FLAG_RECORD_WIRE_FORMAT = 0x00100000

# DNSSEC Record Flags (for RRSIG, DNSKEY, etc.)
DNSSEC_FLAG_SEP = 0x0001  # Secure Entry Point (key signing key)
DNSSEC_FLAG_REVOKE = 0x0080  # Key has been revoked
DNSSEC_FLAG_ZONE = 0x0100  # Zone Key (used for zone signing)

# DNSSEC Algorithms (RFC 4034)
DNSSEC_ALGORITHMS = {
	1: "RSA/MD5",
	2: "DH",
	3: "DSA/SHA-1",
	5: "RSA/SHA-1",
	6: "DSA-NSEC3-SHA1",
	7: "RSASHA1-NSEC3-SHA1",
	8: "RSA/SHA-256",
	10: "RSA/SHA-512",
	12: "ECC-GOST",
	13: "ECDSA/P-256/SHA-256",
	14: "ECDSA/P-384/SHA-384",
	15: "ED25519",
	16: "ED448",
}

# DNSSEC Protocol Values
DNSSEC_PROTOCOL_DNSSEC = 3  # Standard DNSSEC protocol
DNSSEC_PROTOCOL_TLS = 1  # TLS protocol (uncommon in DNS)

# Windows Server 2022 Specific Flags
DNS_RECORD_FLAG_2022_SECURE = 0x00000800  # Windows 2022 enhanced security flag
DNS_RECORD_FLAG_2022_COMPRESSED = 0x00001000  # Windows 2022 compressed format
