from rest_framework import serializers as serializers
from rest_framework_simplejwt import serializers as jwt_serializers

class TokenObtainPairSerializer(jwt_serializers.TokenObtainPairSerializer):

    def validate(self, attrs):
        data = []
        data = super().validate(attrs)
        """ self.user is set in super().validate() which also calls super().validate() """
        data["first_name"] = self.user.first_name or ""
        data["email"] = self.user.email or ""
        data["last_name"] = self.user.last_name or ""
        return data
        

class TokenRefreshSerializer(jwt_serializers.TokenRefreshSerializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        data = super().validate(attrs)
        
        return data