################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: interlock_backend.ldap.guid

# ! Tried doing this with impacket.structure but it doesn't work, had to manually
# ! convert and reverse the byte groups.
#---------------------------------- IMPORTS -----------------------------------#
import struct, uuid, logging
from impacket.structure import Structure
from typing import Union
################################################################################

logger = logging.getLogger(__name__)

DATA_DEF_MS = [
	( True, slice(0,4) ),
	( True, slice(4,6) ),
	( True, slice(6,8) ),
	( True, slice(8,16) ),
]
DATA_DEF_LDAP = [
	# Should be reversed?, slice range
	( True, slice(0,4) ),
	( True, slice(4,6) ),
	( True, slice(6,8) ),
	( False, slice(8,10) ),
	( False, slice(10,16) ),
]

class GUID():
	"""
	src: 
	* https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/49e490b8-f972-45d6-a3a4-99f924998d97
	* https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/001eec5a-7f8b-4293-9e21-ca349392db40
	* https://python-ldap.python.narkive.com/ES1oxGBX/ad-objectguid-conversion-to-string
	* https://pastebin.com/1FQfFUhc
	* https://stackoverflow.com/questions/25299971/python-ldap-converting-objectguid-to-hex-string-and-back
	[MS-DTYP] Section 2.3.4.1 / 2.3.4.2

	For some reason MS GUID Documentation and Online sources differ on Data Structure from the actual
	output on samba-tool with SAMBA LDAP Server(s). Might be a difference between ADDS and LDAP.
	"""

	def __init__(self, guid: Union[bytearray, list, str]):
		self.data = {}
		if isinstance(guid, str):
			self.from_str(guid_str=guid)
		else:
			self.from_bytes(guid_bytes=guid)
		return None

	def from_str(self, guid_str: str):
		# TODO - Finish this if we ever need it, just reverse from_bytes
		self.uuid_str = guid_str
		self.data_bytes_hex = self.uuid_str.split("-")
		# Loop through Byte Group Data definition and create Hex Groups
		for d_index, (d_reverse, d_slice) in enumerate(DATA_DEF_LDAP):
			sliced_hex_list = self.data_bytes_hex[d_slice]
			if d_reverse: sliced_hex_list.reverse()
			self.data[d_index] = "".join(sliced_hex_list)
		return None

	def from_bytes(self, guid_bytes: Union[bytearray, list]):
		self.uuid_str = ""
		# If param is passed within a list of raw entry attributes
		if isinstance(guid_bytes, list):
			guid_bytes = bytearray(guid_bytes[0])
		assert type(guid_bytes) == bytearray
		self.data_bytes_raw = guid_bytes
		# Unpack with Network Byte Ordering
		self.data_bytes_int = struct.unpack('!16B', guid_bytes)
		self.data_bytes_hex = ""

		# Convert Integer Byte Array to Hex and split into list/array
		for b_as_int in self.data_bytes_int:
			self.data_bytes_hex = self.data_bytes_hex + hex(b_as_int).replace("0x",",")
		self.data_bytes_hex = self.data_bytes_hex[1:].split(",")

		# Pad single digit hex numbers with a 0 to the left
		for i, b_as_int in enumerate(self.data_bytes_hex):
			self.data_bytes_hex[i] = b_as_int.rjust(2,"0")

		# Loop through Byte Group Data definition and create UUID String
		for d_index, (d_reverse, d_slice) in enumerate(DATA_DEF_LDAP):
			sliced_hex_list = self.data_bytes_hex[d_slice]
			if d_reverse: sliced_hex_list.reverse()
			self.data[d_index] = "".join(sliced_hex_list)

		for ds in self.data.values():
			self.uuid_str = ds if self.uuid_str == "" else f"{self.uuid_str}-{ds}"
		uuid.UUID(self.uuid_str.replace("-",""))
		return None

	def __str__(self):
		return self.uuid_str

	def __dict__(self):
		return self.data