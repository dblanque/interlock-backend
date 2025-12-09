################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: interlock_backend.ldap.securityIdentifier

# ---------------------------------- IMPORTS --------------------------------- #
import logging
from ldap3 import Attribute as LDAPAttribute
################################################################################

logger = logging.getLogger(__name__)


class SID(object):
	"""
	Returns a normalized Windows SID string given a byte array that contains the SID

	See:
	- https://ldapwiki.com/wiki/ObjectSID
	- https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc962011(v=technet.10)?redirectedfrom=MSDN
	- https://technet.microsoft.com/en-us/library/cc962011.aspx
	- https://msdn.microsoft.com/en-us/library/windows/desktop/aa379597(v=vs.85).aspx
	- https://blogs.msdn.microsoft.com/oldnewthing/20040315-00/?p=40253
	- https://stackoverflow.com/questions/846038/convert-a-python-int-into-a-big-endian-string-of-bytes
	- https://github.com/sspreitzer/python-sid

	# Usage\n
	    from sid import SID

	    # byteArray = SID Byte Array\n
	    byteArray = b'\\x01\\x05\\x00\\x00\\x00\\x00\\x00\\x05\\x15\\x00\\x00\\x00\\x11^\\xb3\\x83j\\x06\\x94\\x00\\x80\\xdbi\\xaa\\x87\\x04\\x00\\x00'\n
	    sid = SID(byteArray)\n
	    print(sid) # S-1-0-21-2209570321-9700970-2859064192-1159
	"""

	def __init__(
		self, security_identifier: list | bytes | bytearray | LDAPAttribute
	):
		if not security_identifier:
			return None

		sid_byte_array = None
		# Raw Values List
		if isinstance(security_identifier, list):
			sid_byte_array = security_identifier[0]
		# Object
		elif hasattr(security_identifier, "raw_values"):
			sid_byte_array = security_identifier.raw_values[0]

		if isinstance(security_identifier, bytes):
			sid_byte_array = bytearray(security_identifier)
		elif isinstance(security_identifier, bytearray):
			sid_byte_array = security_identifier

		if not isinstance(sid_byte_array, (bytes, bytearray)):
			if sid_byte_array is None:
				raise ValueError(
					"sid_byte_array must be a byte array or bytes."
				)
			else:
				_msg = f"Unhandled type for SID Object Initialization ({type(sid_byte_array).__name__})."
				logger.error(_msg)
				raise TypeError(_msg)
		logger.debug("Class SID() in: " + __name__)
		logger.debug("SID Byte Array")
		logger.debug(type(sid_byte_array))
		logger.debug(sid_byte_array)

		self.sid_byte_array = sid_byte_array
		self.revision_level = self.sid_byte_array[0]
		self.subauthority_count = self.sid_byte_array[1]
		# 6 bytes - Identifier Authority
		self.identifier_authority = self._unpack_bytes_big_endian(
			self.sid_byte_array[2:8]
		)
		self.subauthorities = []

		logger.debug("SID Revision Level Byte")
		logger.debug(self.revision_level)
		logger.debug("SID Subauthority Count Byte")
		logger.debug(self.subauthority_count)

		# current index in sid byte array
		offset = 8  # initial starting position
		size = 4
		for c in range(int(str(self.subauthority_count))):
			subAuthority = 0
			e = 0
			for e in range(size):
				subAuthority += self.sid_byte_array[offset + e] << 8 * e
				e += 1
			self.subauthorities.append(subAuthority)
			logger.debug("SID Subauthority Added")
			logger.debug(subAuthority)
			offset += 4

		logger.debug("SID Subauthorities Array/List")
		logger.debug(self.subauthorities)

	def _unpack_bytes_big_endian(self, n):
		"""
		Convert arbitrary number of bytes to int (big endian)

		The struct unpack() method only works with bytes provided with lengths divisible by powers of 2.
		The 48-bit (6-byte) identifier authority value could be padded but instead we'll just unpack it to work with any
		number of bytes

		:param n: list containing bytes to be converted to int (big endian)
		:return: int value of bytes n (big endian)
		"""
		r = 0
		for b in n:
			r = r * 256 + int(b)
		return r

	def __str__(self):
		"""
		Prints SID in standard format

		:return: SID string in standard format
		"""
		logger.debug("SID Revision Level: " + str(self.revision_level))
		logger.debug(
			"SID Identifier Authority: " + str(self.identifier_authority)
		)
		logger.debug("SID Subauthorities: " + str(self.subauthorities))
		sid = "S-{0}-{1}".format(self.revision_level, self.subauthority_count)
		for rid in self.subauthorities:
			sid += "-{0}".format(str(rid))
		return sid
