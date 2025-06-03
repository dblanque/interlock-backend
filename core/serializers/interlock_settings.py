from rest_framework import serializers
from core.models.interlock_settings import (
	InterlockSetting,
	INTERLOCK_SETTING_NAME_CHOICES,
)
from core.constants.attrs.local import LOCAL_ATTR_VALUE


class InterlockSettingSerializer(serializers.ModelSerializer):
	name = serializers.ChoiceField(choices=INTERLOCK_SETTING_NAME_CHOICES)

	class Meta:
		model = InterlockSetting
		fields = "__all__"

	def validate(self, attrs: dict):
		initial_data: dict = self.initial_data
		validated_data = super().validate(attrs)
		if not LOCAL_ATTR_VALUE in self.initial_data:
			raise serializers.ValidationError(
				f"{LOCAL_ATTR_VALUE} field is required."
			)
		param_value = initial_data.get(LOCAL_ATTR_VALUE)
		validated_data[LOCAL_ATTR_VALUE] = param_value
		return validated_data