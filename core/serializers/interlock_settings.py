from rest_framework import serializers
from core.models.interlock_settings import InterlockSetting, INTERLOCK_SETTING_NAME_CHOICES


class InterlockSettingSerializer(serializers.ModelSerializer):
	name = serializers.ChoiceField(choices=INTERLOCK_SETTING_NAME_CHOICES)

	class Meta:
		model = InterlockSetting
		fields = "__all__"
