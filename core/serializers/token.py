from rest_framework import serializers as serializers
from rest_framework_simplejwt import serializers as jwt_serializers
from core.models.choices.log import LOG_CLASS_USER, LOG_ACTION_LOGIN
from core.config.runtime import RuntimeSettings
from core.models.user import User
from core.exceptions import otp as exc_otp
from core.views.mixins.logs import LogMixin
from rest_framework.exceptions import AuthenticationFailed
from core.views.mixins.totp import get_user_totp_device, validate_user_otp
import re

DBLogMixin = LogMixin()


def user_auth_fail_conditions(user: User):
	if not user.is_anonymous and user.is_enabled:
		return True


class TokenObtainPairSerializer(jwt_serializers.TokenObtainPairSerializer):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		self.fields["totp_code"] = serializers.CharField(required=False)
		self.fields["recovery_code"] = serializers.CharField(required=False)

	def validate(self, attrs):
		self.user: User
		data = []
		data = super().validate(attrs)
		""" self.user is set in super().validate() which also calls super().validate() """

		if not user_auth_fail_conditions(self.user) is True:
			raise AuthenticationFailed

		# TOTP
		if get_user_totp_device(user=self.user, confirmed=True):
			if "recovery_code" in attrs:
				r_code = attrs["recovery_code"]
				if r_code not in self.user.recovery_codes:
					raise exc_otp.OTPInvalidRecoveryCode
				self.user.recovery_codes.remove(r_code)
				self.user.save()
			else:
				if "totp_code" not in attrs:
					raise exc_otp.OTPRequired
				regex = r"^[0-9]{6}$"
				if not re.match(regex, attrs["totp_code"]):
					raise exc_otp.OTPInvalidData
				validate_user_otp(user=self.user, data=attrs)

		data["first_name"] = self.user.first_name or ""
		data["last_name"] = self.user.last_name or ""
		data["email"] = self.user.email or ""
		data["user_type"] = self.user.user_type or ""
		if self.user.is_superuser or self.user.username == "admin":
			data["admin_allowed"] = True

		DBLogMixin.log(
			user_id=self.user.id,
			operation_type=LOG_ACTION_LOGIN,
			log_target_class=LOG_CLASS_USER
		)
		return data


class TokenRefreshSerializer(jwt_serializers.TokenRefreshSerializer):
	refresh = serializers.CharField()

	def validate(self, attrs):
		self.user: User
		data = super().validate(attrs)
		if not user_auth_fail_conditions(self.user) is True:
			raise AuthenticationFailed
		return data


class OTPTokenSerializer(TokenRefreshSerializer):
	totp_code = serializers.IntegerField()
