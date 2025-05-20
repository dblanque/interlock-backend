################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.structs.ldap_dns_record
# Contains the Models for DNS Record Types
#
# ---------------------------------- IMPORTS -----------------------------------#
from struct import unpack, pack
from impacket.structure import Structure
from core.models.types.ldap_dns_record import RecordTypes
from core.constants.dns import *
from typing import Iterable
import socket
import datetime
import sys
import logging
from typing import TypedDict, Required, NotRequired
################################################################################

logger = logging.getLogger(__name__)

RecordMapping = TypedDict(
	"RecordMapping",
	{
		"name": Required[str],
		"class": Required[str],
		"main_field": NotRequired[str],
		"fields": Required[list[str]],
		"multi_record": NotRequired[bool],
	},
)

RECORD_TYPE_ENUM_PREFIX = "DNS_RECORD_TYPE_"
RECORD_MAPPINGS: dict[RecordMapping]
RECORD_MAPPINGS = {
	RecordTypes.DNS_RECORD_TYPE_ZERO.value: {
		"name": "ZERO",
		"class": "DNS_RPC_RECORD_TS",
		"fields": [LDNS_ATTR_TOMBSTONE_TIME],
	},
	RecordTypes.DNS_RECORD_TYPE_A.value: {
		"name": "A",
		"class": "DNS_RPC_RECORD_A",
		"fields": [LDNS_ATTR_IPV4_ADDRESS],
		"multi_record": True,
	},
	RecordTypes.DNS_RECORD_TYPE_AAAA.value: {
		"name": "AAAA",
		"class": "DNS_RPC_RECORD_AAAA",
		"fields": [LDNS_ATTR_IPV6_ADDRESS],
		"multi_record": True,
	},
	RecordTypes.DNS_RECORD_TYPE_NS.value: {
		"name": "NS",
		"class": "DNS_RPC_RECORD_NODE_NAME",
		"fields": [LDNS_ATTR_NAME_NODE],
		"multi_record": True,
	},
	RecordTypes.DNS_RECORD_TYPE_CNAME.value: {
		"name": "CNAME",
		"class": "DNS_RPC_RECORD_NODE_NAME",
		"fields": [LDNS_ATTR_NAME_NODE],
		"multi_record": False,
	},
	RecordTypes.DNS_RECORD_TYPE_DNAME.value: {
		"name": "DNAME",
		"class": "DNS_RPC_RECORD_NODE_NAME",
		"fields": [LDNS_ATTR_NAME_NODE],
		"multi_record": False,
	},
	RecordTypes.DNS_RECORD_TYPE_SOA.value: {
		"name": "SOA",
		"class": "DNS_RPC_RECORD_SOA",
		"main_field": LDNS_ATTR_SOA_PRIMARY_NS,
		"fields": [
			LDNS_ATTR_SOA_SERIAL,
			LDNS_ATTR_SOA_REFRESH,
			LDNS_ATTR_SOA_RETRY,
			LDNS_ATTR_SOA_EXPIRE,
			LDNS_ATTR_SOA_MIN_TTL,
			LDNS_ATTR_SOA_PRIMARY_NS,
			LDNS_ATTR_SOA_EMAIL,
		],
		"multi_record": False,
	},
	RecordTypes.DNS_RECORD_TYPE_TXT.value: {
		"name": "TXT",
		"class": "DNS_RPC_RECORD_STRING",
		"fields": [LDNS_ATTR_STRING_DATA],
		"multi_record": True,
	},
	RecordTypes.DNS_RECORD_TYPE_X25.value: {
		"name": "X25",
		"class": "DNS_RPC_RECORD_STRING",
		"fields": [LDNS_ATTR_STRING_DATA],
		"multi_record": True,
	},
	RecordTypes.DNS_RECORD_TYPE_ISDN.value: {
		"name": "ISDN",
		"class": "DNS_RPC_RECORD_STRING",
		"fields": [LDNS_ATTR_STRING_DATA],
		"multi_record": True,
	},
	RecordTypes.DNS_RECORD_TYPE_LOC.value: {
		"name": "LOC",
		"class": "DNS_RPC_RECORD_STRING",
		"fields": [LDNS_ATTR_STRING_DATA],
		"multi_record": True,
	},
	RecordTypes.DNS_RECORD_TYPE_HINFO.value: {
		"name": "HINFO",
		"class": "DNS_RPC_RECORD_STRING",
		"fields": [LDNS_ATTR_STRING_DATA],
		"multi_record": True,
	},
	RecordTypes.DNS_RECORD_TYPE_MX.value: {
		"name": "MX",
		"class": "DNS_RPC_RECORD_NAME_PREFERENCE",
		"main_field": LDNS_ATTR_MX_SERVER,
		"fields": [LDNS_ATTR_MX_PRIORITY, LDNS_ATTR_MX_SERVER],
		"multi_record": True,
	},
	RecordTypes.DNS_RECORD_TYPE_SIG.value: {
		"name": "SIG",
		"class": "DNS_RPC_RECORD_SIG",
		"main_field": LDNS_ATTR_SIG_SIGNATURE_INFO,
		"fields": [
			LDNS_ATTR_SIG_TYPE_COVERED,
			LDNS_ATTR_SIG_ALGORITHM,
			LDNS_ATTR_SIG_LABEL_COUNT,
			LDNS_ATTR_SIG_ORIGINAL_TTL,
			LDNS_ATTR_SIG_SIG_EXPIRATION,
			LDNS_ATTR_SIG_SIG_INCEPTION,
			LDNS_ATTR_SIG_KEY_TAG,
			LDNS_ATTR_SIG_NAME_SIGNER,
			LDNS_ATTR_SIG_SIGNATURE_INFO,
		],
	},
	RecordTypes.DNS_RECORD_TYPE_KEY.value: {
		"name": "KEY",
		"class": None,
		"fields": [],
	},
	RecordTypes.DNS_RECORD_TYPE_SRV.value: {
		"name": "SRV",
		"class": "DNS_RPC_RECORD_SRV",
		"main_field": LDNS_ATTR_SRV_TARGET,
		"fields": [
			LDNS_ATTR_SRV_PRIORITY,
			LDNS_ATTR_SRV_WEIGHT,
			LDNS_ATTR_SRV_PORT,
			LDNS_ATTR_SRV_TARGET,
		],
		"multi_record": True,
	},
	RecordTypes.DNS_RECORD_TYPE_PTR.value: {
		"name": "PTR",
		"class": "DNS_RPC_RECORD_NODE_NAME",
		"fields": [LDNS_ATTR_NAME_NODE],
		"multi_record": False,
	},
	RecordTypes.DNS_RECORD_TYPE_WINS.value: {
		"name": "WINS",
		"class": None,
		"fields": [],
	},
	# DEPRECATED BY RFCs
	RecordTypes.DNS_RECORD_TYPE_MB.value: {
		"name": "MB",
		"class": "DNS_RPC_RECORD_NODE_NAME",
		"fields": [LDNS_ATTR_NAME_NODE],
	},
	RecordTypes.DNS_RECORD_TYPE_MR.value: {
		"name": "MR",
		"class": "DNS_RPC_RECORD_NODE_NAME",
		"fields": [LDNS_ATTR_NAME_NODE],
	},
	RecordTypes.DNS_RECORD_TYPE_MG.value: {
		"name": "MG",
		"class": "DNS_RPC_RECORD_NODE_NAME",
		"fields": [LDNS_ATTR_NAME_NODE],
	},
	RecordTypes.DNS_RECORD_TYPE_MD.value: {
		"name": "MD",
		"class": "DNS_RPC_RECORD_NODE_NAME",
		"fields": [LDNS_ATTR_NAME_NODE],
	},
	RecordTypes.DNS_RECORD_TYPE_MF.value: {
		"name": "MF",
		"class": "DNS_RPC_RECORD_NODE_NAME",
		"fields": [LDNS_ATTR_NAME_NODE],
	},
}


def record_to_dict(record: "DNS_RECORD", ts=False):
	thismodule = sys.modules[__name__]

	# For original reference see print_record
	try:
		rtype = RECORD_MAPPINGS[record[LDNS_ATTR_STRUCT_TYPE]]["name"]
	except KeyError:
		rtype = "Unsupported"

	record_dict = {}
	record_dict[LDNS_ATTR_TOMBSTONED] = False

	# Check if record is Tombstoned / Inactive
	if isinstance(ts, bool):
		record_dict[LDNS_ATTR_TOMBSTONED] = ts
	elif isinstance(ts, str):
		if len(ts) > 0:
			record_dict[LDNS_ATTR_TOMBSTONED] = ts.lower() == "true"
	elif isinstance(ts, Iterable):
		if len(ts) >= 1:
			record_dict[LDNS_ATTR_TOMBSTONED] = (
				ts[0] == True or str(ts[0]).lower() == "true"
			)

	record_dict[LDNS_ATTR_TYPE] = record[LDNS_ATTR_STRUCT_TYPE]
	record_dict[LDNS_ATTR_TYPE_NAME] = rtype
	record_dict[LDNS_ATTR_SERIAL] = record[LDNS_ATTR_STRUCT_SERIAL]

	# If the Record Type is Mapped to a Class
	if record[LDNS_ATTR_STRUCT_TYPE] in RECORD_MAPPINGS:
		# Initialize the class with the record Data key
		data = getattr(
			thismodule, RECORD_MAPPINGS[record[LDNS_ATTR_STRUCT_TYPE]]["class"]
		)(record[LDNS_ATTR_STRUCT_DATA])

		# ! Print class ! #
		logger.debug(
			getattr(
				thismodule,
				RECORD_MAPPINGS[record[LDNS_ATTR_STRUCT_TYPE]]["class"],
			)
		)

		fqdnFields = [
			LDNS_ATTR_NAME_NODE,
			LDNS_ATTR_MX_SERVER,
			LDNS_ATTR_SRV_TARGET,
			LDNS_ATTR_SOA_PRIMARY_NS,
			LDNS_ATTR_SOA_EMAIL,
		]
		# For each value field mapped for this Record Type set it
		for valueField in RECORD_MAPPINGS[record[LDNS_ATTR_STRUCT_TYPE]][
			"fields"
		]:
			try:
				if valueField == LDNS_ATTR_TOMBSTONE_TIME:
					record_dict[valueField] = data.toDatetime()
				elif (
					valueField == LDNS_ATTR_IPV4_ADDRESS
					and record[LDNS_ATTR_STRUCT_TYPE]
					== RecordTypes.DNS_RECORD_TYPE_A.value
				):
					record_dict[valueField] = data.formatCanonical()
				elif (
					valueField == LDNS_ATTR_IPV6_ADDRESS
					and record[LDNS_ATTR_STRUCT_TYPE]
					== RecordTypes.DNS_RECORD_TYPE_AAAA.value
				):
					record_dict[valueField] = data.formatCanonical()
				elif valueField == LDNS_ATTR_STRING_DATA:
					record_dict[valueField] = data[valueField].toString()
				elif valueField in fqdnFields:
					record_dict[valueField] = data[valueField].toFqdn()
				else:
					record_dict[valueField] = data[valueField]
			except Exception as e:
				# data.dump()
				logger.error(record_dict)
				logger.error(valueField)
				logger.exception(e)
				raise e
	return record_dict


class DNS_RECORD(Structure):
	"""
	dnsRecord - used in LDAP
	[MS-DNSP] section 2.3.2.2
	"""

	structure = (
		(LDNS_ATTR_STRUCT_DATA_LENGTH, "<H-Data"),
		(LDNS_ATTR_STRUCT_TYPE, "<H"),
		(LDNS_ATTR_STRUCT_VERSION, "B=5"),
		(LDNS_ATTR_STRUCT_RANK, "B"),
		(LDNS_ATTR_STRUCT_FLAGS, "<H=0"),
		(LDNS_ATTR_STRUCT_SERIAL, "<L"),
		(LDNS_ATTR_STRUCT_TTL_SECONDS, ">L"),
		(LDNS_ATTR_STRUCT_RESERVED, "<L=0"),
		(LDNS_ATTR_STRUCT_TIMESTAMP, "<L=0"),
		(LDNS_ATTR_STRUCT_DATA, ":"),
	)

	def __bytedata__(self):
		return self.getData()

	def __str__(self):
		return str(record_to_dict(self))

	def __dict__(self):
		return record_to_dict(self)

	def __getTTL__(self):
		return self[LDNS_ATTR_STRUCT_TTL_SECONDS]


# Note that depending on whether we use RPC or LDAP all the DNS_RPC_XXXX
# structures use DNS_RPC_NAME when communication is over RPC,
# but DNS_COUNT_NAME is the way they are stored in LDAP.
#
# Since LDAP is the primary goal of this script we use that, but for use
# over RPC the DNS_COUNT_NAME in the structures must be replaced with DNS_RPC_NAME,
# which is also consistent with how MS-DNSP describes it.


class DNS_RPC_NAME(Structure):
	"""
	DNS_RPC_NAME
	Used for FQDNs in RPC communication.
	MUST be converted to DNS_COUNT_NAME for LDAP
	[MS-DNSP] section 2.2.2.2.1
	"""

	structure = (
		(LDNS_ATTR_STRUCT_NAME_LENGTH, "B-dnsName"),
		(LDNS_ATTR_STRUCT_DNS_NAME, ":"),
	)

	def toString(self):
		labels = ""
		for i in range(self[LDNS_ATTR_STRUCT_NAME_LENGTH]):
			# Convert byte array of ASCII or UTF-8 data from (single?)
			# byte character.
			labels = labels + chr(self[LDNS_ATTR_STRUCT_DNS_NAME][i])
		return labels

	def toRPCName(self, valueString):
		length = len(valueString)
		dnsName = []
		for i in range(length):
			# Convert character to ASCII single byte character.
			dnsName.append(ord(valueString[i]))
		lengthToPack = pack("B", length)
		self[LDNS_ATTR_STRUCT_NAME_LENGTH] = lengthToPack
		self[LDNS_ATTR_STRUCT_DNS_NAME] = bytes(dnsName)


class DNS_COUNT_NAME(Structure):
	"""
	DNS_COUNT_NAME
	Used for FQDNs in LDAP communication
	MUST be converted to DNS_RPC_NAME for RPC communication
	[MS-DNSP] section 2.2.2.2.2
	"""

	structure = (
		(LDNS_ATTR_STRUCT_LENGTH, "B-RawName"),
		(LDNS_ATTR_STRUCT_LABEL_COUNT, "B"),
		(LDNS_ATTR_STRUCT_RAW_NAME, ":"),
	)

	def insert_field_to_struct(self, fieldName=None, fieldStructVal=None):
		"""
		Insert a field into the byte structure before the defaults
		"""
		oldStruct = self.structure
		self.structure = [(fieldName, fieldStructVal)]
		self.structure.extend(list(oldStruct))
		self.structure = tuple(self.structure)

	def setCastField(self, fieldName, value, cast=int):
		"""
		Set value for an inserted field in the structure
		You may cast to a specific type, default is int
		- fieldName: The name of the field
		- value: The value of the field
		- cast: The type to cast (default: int)
		"""
		self[fieldName] = cast(value)

	def toFqdn(self):
		ind = 0
		labels = []
		for i in range(self[LDNS_ATTR_STRUCT_LABEL_COUNT]):
			try:
				nextlen = unpack(
					"B", self[LDNS_ATTR_STRUCT_RAW_NAME][ind : ind + 1]
				)[0]
				labels.append(
					self[LDNS_ATTR_STRUCT_RAW_NAME][
						ind + 1 : ind + 1 + nextlen
					].decode("utf-8")
				)
				ind += nextlen + 1
			except Exception as e:
				logger.error("Unable to UNPACK Raw Name in DNS Record")
				logger.error(
					f"Length: ({str(type(self[LDNS_ATTR_STRUCT_LENGTH]))}): {self[LDNS_ATTR_STRUCT_LENGTH]}"
				)
				logger.error(
					f"Label Count: ({str(type(self[LDNS_ATTR_STRUCT_LABEL_COUNT]))}): {self[LDNS_ATTR_STRUCT_LABEL_COUNT]}"
				)
				logger.error(
					f"Raw Name: ({str(type(self[LDNS_ATTR_STRUCT_RAW_NAME]))}): {self[LDNS_ATTR_STRUCT_RAW_NAME]}"
				)
				raise e

		# For the final dot
		labels.append("")
		return ".".join(labels)

	def toCountName(self, v_str: str, add_null_at_end=True):
		# Structure:
		# String -> FQDN -> 1-byte Label Length COUNT for the subsequent label

		length = len(v_str)
		split_string = v_str.rstrip(".").split(".")
		label_count = len(split_string)
		if label_count <= 0:
			label_count = 0
		new_string = bytes()
		for i in range(label_count):
			new_string += pack("B", len(split_string[i])) + (
				bytes(split_string[i], "utf-8")
			)

		# Add 1 to Length as it must include the NULL Terminator Byte
		self[LDNS_ATTR_STRUCT_LENGTH] = length + 1
		self[LDNS_ATTR_STRUCT_LABEL_COUNT] = label_count
		try:
			if add_null_at_end:
				self[LDNS_ATTR_STRUCT_RAW_NAME] = new_string + b"\x00"
			else:
				self[LDNS_ATTR_STRUCT_RAW_NAME] = new_string
		except Exception as e:
			print(e)
			raise Exception("Error setting RawName key in Data Structure")

		# Impacket Structure should handle this, but just in case...
		if len(self[LDNS_ATTR_STRUCT_RAW_NAME]) > 256:
			print(self[LDNS_ATTR_STRUCT_RAW_NAME])
			raise ValueError("Raw Name Length cannot be more than 256")


class DNS_RPC_NODE(Structure):
	"""
	DNS_RPC_NODE
	Defines a structure used as a header for a list of DNS_RPC_RECORD structs
	[MS-DNSP] section 2.2.2.2.3
	"""

	structure = (
		(LDNS_ATTR_STRUCT_RPC_LENGTH, ">H"),
		(LDNS_ATTR_STRUCT_RECORD_COUNT, ">H"),
		(LDNS_ATTR_STRUCT_RPC_FLAGS, ">L"),
		(LDNS_ATTR_STRUCT_RPC_CHILD_COUNT, ">L"),
		(LDNS_ATTR_STRUCT_RPC_NODE_NAME, ":"),
	)


class DNS_RPC_RECORD_A(Structure):
	"""
	DNS_RPC_RECORD_A
	Contains an IPv4 Address
	[MS-DNSP] section 2.2.2.2.4.1
	"""

	structure = ((LDNS_ATTR_IPV4_ADDRESS, ":"),)

	def formatCanonical(self):
		"""
		formatCanonical (IPv4)
		Returns IPv4 Bytes as String Address
		"""
		return socket.inet_ntop(socket.AF_INET, self[LDNS_ATTR_IPV4_ADDRESS])

	def fromCanonical(self, canonical):
		"""
		fromCanonical (IPv4)
		Returns IPv4 String Address as Bytes
		"""
		self[LDNS_ATTR_IPV4_ADDRESS] = socket.inet_pton(
			socket.AF_INET, canonical)


class DNS_RPC_RECORD_NODE_NAME(Structure):
	"""
	DNS_RPC_RECORD_NODE_NAME

	This Structure contains information about any of the following DNS Types:

	- DNS_TYPE_PTR
	- DNS_TYPE_NS
	- DNS_TYPE_CNAME
	- DNS_TYPE_DNAME
	- DNS_TYPE_MB
	- DNS_TYPE_MR
	- DNS_TYPE_MG
	- DNS_TYPE_MD
	- DNS_TYPE_MF

	[MS-DNSP] section 2.2.2.2.4.2
	"""

	structure = ((LDNS_ATTR_NAME_NODE, ":", DNS_COUNT_NAME),)


class DNS_RPC_RECORD_SOA(Structure):
	"""
	DNS_RPC_RECORD_SOA
	This structure contains information for a Start Of Authority Record
	[MS-DNSP] section 2.2.2.2.4.3
	"""

	structure = (
		(LDNS_ATTR_SOA_SERIAL, ">L"),
		(LDNS_ATTR_SOA_REFRESH, ">L"),
		(LDNS_ATTR_SOA_RETRY, ">L"),
		(LDNS_ATTR_SOA_EXPIRE, ">L"),
		(LDNS_ATTR_SOA_MIN_TTL, ">L"),
		(LDNS_ATTR_SOA_PRIMARY_NS, ":", DNS_COUNT_NAME),
		(LDNS_ATTR_SOA_EMAIL, ":", DNS_COUNT_NAME),
	)

	def setField(self, fieldName, value):
		self[fieldName] = int(value)

	def addCountName(self, valueString):
		countName = DNS_COUNT_NAME()
		countName.toCountName(v_str=valueString, add_null_at_end=True)
		return countName.getData()


class DNS_RPC_RECORD_NULL(Structure):
	"""
	DNS_RPC_RECORD_NULL

	Contains information for any record for which there is no more
	specific DNS_RPC_RECORD structure.

	[MS-DNSP] section 2.2.2.2.4.4
	"""

	structure = (("bData", ":"),)


class DNS_RPC_RECORD_STRING(Structure):
	"""
	DNS_RPC_RECORD_STRING

	This Structure specifies information about a DNS record of
	any of the following types:
	- DNS_TYPE_HINFO
	- DNS_TYPE_ISDN
	- DNS_TYPE_TXT
	- DNS_TYPE_X25
	- DNS_TYPE_LOC

	[MS-DNSP] section 2.2.2.2.4.6
	"""

	structure = ((LDNS_ATTR_STRING_DATA, ":", DNS_RPC_NAME),)


# TODO
##   DNS_RPC_RECORD_MAIL_ERROR                  | 2.2.2.2.4.7


class DNS_RPC_RECORD_NAME_PREFERENCE(Structure):
	"""
	DNS_RPC_RECORD_NAME_PREFERENCE

	This Structure specifies information about a DNS record of
	any of the following types:

	- DNS_TYPE_MX
	- DNS_TYPE_AFSDB
	- DNS_TYPE_RT

	[MS-DNSP] section 2.2.2.2.4.8
	"""

	structure = (
		(LDNS_ATTR_MX_PRIORITY, ">H"),
		(LDNS_ATTR_MX_SERVER, ":", DNS_COUNT_NAME),
	)


class DNS_RPC_RECORD_SIG(Structure):
	"""
	DNS_RPC_RECORD_SIG

	This structure contains information about cryptographic public key
	signatures as specified in section 4 of RFC-2535

	[MS-DNSP] section 2.2.2.2.4.9
	"""

	structure = (
		(LDNS_ATTR_SIG_TYPE_COVERED, ">H"),  # 2 bytes - Unsigned Short
		(LDNS_ATTR_SIG_ALGORITHM, ">B"),  # 1 byte - Unsigned Char
		(LDNS_ATTR_SIG_LABEL_COUNT, ">B"),  # 1 byte - Unsigned Char
		(LDNS_ATTR_SIG_ORIGINAL_TTL, ">L"),  # 4 bytes - Unsigned Long
		(LDNS_ATTR_SIG_SIG_EXPIRATION, ">L"),  # 4 bytes - Unsigned Long
		(LDNS_ATTR_SIG_SIG_INCEPTION, ">L"),  # 4 bytes - Unsigned Long
		(LDNS_ATTR_SIG_KEY_TAG, ">H"),  # 2 bytes - Unsigned Short
		(LDNS_ATTR_SIG_NAME_SIGNER, ":", DNS_COUNT_NAME),  # Variable
		(LDNS_ATTR_SIG_SIGNATURE_INFO, ":"),  # Variable
	)


# TODO
## DNS_RPC_RECORD_NSEC      | 2.2.2.2.4.11
## DNS_RPC_RECORD_DS        | 2.2.2.2.4.12
## DNS_RPC_RECORD_KEY       | 2.2.2.2.4.13
## DNS_RPC_RECORD_DHCID     | 2.2.2.2.4.14
## DNS_RPC_RECORD_DNSKEY    | 2.2.2.2.4.15
class DNS_RPC_RECORD_AAAA(Structure):
	"""
	DNS_RPC_RECORD_AAAA
	[MS-DNSP] section 2.2.2.2.4.16
	"""

	structure = ((LDNS_ATTR_IPV6_ADDRESS, "!16s"),)

	def formatCanonical(self):
		"""
		formatCanonical (IPv6)
		Returns IPv6 Bytes as String Address
		"""
		return socket.inet_ntop(socket.AF_INET6, self[LDNS_ATTR_IPV6_ADDRESS])
		# return self['ipv6Address']

	def fromCanonical(self, canonical):
		"""
		fromCanonical (IPv6)
		Returns IPv6 String Address without separators
		"""
		self[LDNS_ATTR_IPV6_ADDRESS] = socket.inet_pton(
			socket.AF_INET6, canonical)
		# self['ipv6Address'] = str(canonical).replace(':','')


# TODO
## DNS_RPC_RECORD_NXT       | 2.2.2.2.4.17


class DNS_RPC_RECORD_SRV(Structure):
	"""
	DNS_RPC_RECORD_SRV
	[MS-DNSP] section 2.2.2.2.4.18
	"""

	structure = (
		(LDNS_ATTR_SRV_PRIORITY, ">H"),
		(LDNS_ATTR_SRV_WEIGHT, ">H"),
		(LDNS_ATTR_SRV_PORT, ">H"),
		(LDNS_ATTR_SRV_TARGET, ":", DNS_COUNT_NAME),
	)

	def setField(self, fieldName, value):
		self[fieldName] = int(value)

	def addCountName(self, valueString):
		countName = DNS_COUNT_NAME()
		countName.toCountName(v_str=valueString, add_null_at_end=True)
		return countName.getData()


# TODO
## DNS_RPC_RECORD_ATMA      | 2.2.2.2.4.19
## DNS_RPC_RECORD_NAPTR     | 2.2.2.2.4.20
## DNS_RPC_RECORD_WINS      | 2.2.2.2.4.21
## DNS_RPC_RECORD_WINSR     | 2.2.2.2.4.22
class DNS_RPC_RECORD_TS(Structure):
	"""
	DNS_RPC_RECORD_TS
	[MS-DNSP] section 2.2.2.2.4.23
	"""

	structure = ((LDNS_ATTR_TS_ENTOMBED_AT, "<Q"),)

	def toDatetime(self):
		microseconds = self[LDNS_ATTR_TS_ENTOMBED_AT] / 10.0
		return datetime.datetime(1601, 1, 1) + datetime.timedelta(
			microseconds=microseconds
		)


# TODO
## DNS_RPC_RECORD_NSEC3     | 2.2.2.2.4.24
## DNS_RPC_RECORD_NSEC3PARAM| 2.2.2.2.4.25
## DNS_RPC_RECORD_TLSA      | 2.2.2.2.4.26
## DNS_RPC_RECORD_UNKNOWN   | 2.2.2.2.4.27
