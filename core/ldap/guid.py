################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: interlock_backend.ldap.guid

# ! Tried doing this with impacket.structure but it doesn't work, had to manually
# ! convert and reverse the byte groups.
# ---------------------------------- IMPORTS --------------------------------- #
import struct
import uuid
import logging
from typing import Union
################################################################################

logger = logging.getLogger(__name__)

# Reverse Bytes slice, byte slice indices
DATA_DEF_MS = [
	(True, slice(0, 4)),
	(True, slice(4, 6)),
	(True, slice(6, 8)),
	(True, slice(8, 16)),
]

# Reverse Bytes slice, byte slice indices
DATA_DEF_LDAP = [
	(True, slice(0, 4)),
	(True, slice(4, 6)),
	(True, slice(6, 8)),
	(False, slice(8, 10)),
	(False, slice(10, 16)),
]


class GUID:
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

	SAMPLE DATA FROM TEST LDAP SERVER:
	- ldbsearch -H /var/lib/samba/private/sam.ldb name realm objectGUID objectSID|grep -A 3 "groupname"
	  - name: group1
	    - objectGUID (bytes): b'\xde\xbe]\xb1\xc0\x7f\xbeG\x97;=\x05\x8a\n0`'
	    - objectGUID (str): b15dbede-7fc0-47be-973b-3d058a0a3060
	  - name: group2
	    - objectGUID (bytes): b'\xb4c\xb7\xf3\xc3\xe2L@\xa5\xea7\x81[\xdd\xea\x08'
	    - objectGUID (str): f3b763b4-e2c3-404c-a5ea-37815bddea08
	"""

	def __init__(self, guid: Union[bytearray, list, str]):
		self.data = {}
		if isinstance(guid, str):
			self.from_str(guid_str=guid)
		else:
			if isinstance(guid, bytes):
				try:
					guid = bytearray(guid)
				except Exception as e:
					raise ValueError(
						"Could not implicitly convert bytes to bytearray."
					) from e
			self.from_bytes(guid_bytes=guid)
		return None

	def from_str(self, guid_str: str):
		# Validate the GUID string format
		try:
			uuid.UUID(guid_str)
		except ValueError as e:
			logger.error(f"Invalid GUID string: {guid_str}")
			raise e

		parts = guid_str.split("-")
		if len(parts) != 5:
			raise ValueError(
				"Invalid GUID format, must have 5 parts separated by '-'"
			)

		byte_list = [0] * 16

		for group_index, (reverse_flag, byte_slice) in enumerate(DATA_DEF_LDAP):
			part = parts[group_index]

			# Split part into two-character hex pairs
			hex_pairs = [part[i : i + 2] for i in range(0, len(part), 2)]
			if len(hex_pairs) * 2 != len(part):
				raise ValueError(
					f"Part {group_index} '{part}' has invalid length"
				)

			# Reverse the hex pairs if required
			if reverse_flag:
				hex_pairs = list(reversed(hex_pairs))

			# Convert hex pairs to integers (bytes)
			try:
				bytes_group = [int(hp, 16) for hp in hex_pairs]
			except ValueError as e:
				raise ValueError(
					f"Invalid hex in part {group_index} '{part}': {e}"
				)

			# Check if the number of bytes matches the slice length
			start = byte_slice.start
			stop = byte_slice.stop
			expected_length = stop - start
			if len(bytes_group) != expected_length:
				raise ValueError(
					f"Part {group_index} has {len(bytes_group)} bytes, expected {expected_length}"
				)

			# Assign bytes to the correct positions in the byte list
			for i in range(len(bytes_group)):
				byte_list[start + i] = bytes_group[i]

		# Convert the list to a bytearray and process through from_bytes
		guid_bytes = bytearray(byte_list)
		self.from_bytes(guid_bytes)

		# Verify the generated UUID string matches the input
		if self.uuid_str != guid_str:
			raise ValueError(
				"Conversion from string to bytes and back to string failed. Generated UUID does not match input."
			)

		return None

	def from_bytes(self, guid_bytes: Union[bytearray, list]):
		self.uuid_str = ""
		# If param is passed within a list of raw entry attributes
		if isinstance(guid_bytes, list):
			try:
				guid_bytes = bytearray(guid_bytes[0])
			except Exception as e:
				raise ValueError(
					"Could not implicitly convert list to bytearray."
				) from e
		assert isinstance(guid_bytes, bytearray), (
			"guid_bytes must be a bytearray"
		)
		self.data_bytes_raw = guid_bytes
		# Unpack with Network Byte Ordering
		try:
			self.data_bytes_int = struct.unpack("!16B", guid_bytes)
		except:
			logger.error("Invalid struct length, could not unpack.")
			raise
		self.data_bytes_hex = []

		# Convert Integer Byte Array to Hex and split into list/array
		for b_as_int in self.data_bytes_int:
			self.data_bytes_hex.append(format(b_as_int, "02x"))

		# Loop through Byte Group Data definition and create UUID String
		self.data = {}
		for d_index, (d_reverse, d_slice) in enumerate(DATA_DEF_LDAP):
			sliced_hex_list = self.data_bytes_hex[d_slice]
			if d_reverse:
				sliced_hex_list = list(reversed(sliced_hex_list))
			self.data[d_index] = "".join(sliced_hex_list)

		# Construct the UUID string from the data dictionary
		self.uuid_str = "-".join(
			[self.data[i] for i in range(len(DATA_DEF_LDAP))]
		)

		# Validate the constructed UUID string
		try:
			uuid.UUID(self.uuid_str)
		except ValueError as e:
			logger.error(f"Generated invalid UUID string: {self.uuid_str}")
			raise e

		return None

	def __str__(self):
		return self.uuid_str

	def __repr__(self):
		return f"GUID('{self.uuid_str}')"

	def __dict__(self):
		return self.data
