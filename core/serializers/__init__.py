from rest_framework import serializers
from base64 import b64decode, b64encode

class BinaryField(serializers.Field):
	"""
	"""
	def to_representation(self, value: bytes) -> str:
		"""Binary data is serialized as base64"""
		return b64encode(value).decode("ascii")

	def to_internal_value(self, data: str) -> bytes:
		# If it's a string, it should be base64-encoded data
		if isinstance(data, str):
			return memoryview(b64decode(data.encode("ascii")))
		return data
