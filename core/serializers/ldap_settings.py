from rest_framework import serializers
from core.models.ldap_settings import LDAPSetting, LDAPPreset

class LDAPPresetSerializer(serializers.ModelSerializer):
    class Meta:
        model = LDAPPreset
        fields = "__all__"

class LDAPSettingSerializer(serializers.ModelSerializer):
    name = serializers.CharField(validators=[])
    preset = LDAPPresetSerializer(source="ldap_preset", read_only=True)
    class Meta:
        model = LDAPSetting
        fields = "__all__"
