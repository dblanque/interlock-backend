from rest_framework import serializers
from rest_framework.exceptions import ValidationError


class AliasCharField(serializers.CharField):
	def __init__(self, aliases=None, **kwargs):
		self.aliases = aliases or []
		super().__init__(**kwargs)

	def to_internal_value(self, data):
		# Check all possible field names (original + aliases)
		for field_name in [self.field_name] + self.aliases:
			if field_name in data:
				return super().to_internal_value(data[field_name])

		# If no field found and field is required, raise validation error
		if self.required:
			raise ValidationError(
				f"Field '{self.field_name}' (or aliases: {self.aliases}) is required."
			)
		return None  # Only reached if required=False

	def get_attribute(self, instance):
		# Handle all aliases during serialization (output)
		for field_name in [self.field_name] + self.aliases:
			try:
				return super().get_attribute(instance)
			except AttributeError:
				continue
		return None
