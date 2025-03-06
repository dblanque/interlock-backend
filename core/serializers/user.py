import re
from rest_framework import serializers
from core.models.application import User

FIELD_VALIDATORS = {
    "username":         "ldap_user",    # username
    "password":             None,       # password
    "mail":                 None,       # email
    "givenName":            None,       # first_name
    "sn":                   None,       # last_name
    "initials":             None,       # initials
    "telephoneNumber":      None,       # phone_number
    "wWWHomePage":          None,       # webpage
    "streetAddress":        None,       # street_address
    "postalCode":           None,       # postal_code
    "l":                    None,       # town
    "st":                   None,       # state_province
    "co":                   None        # country
}

ldap_user_pattern = ".*[\]\[\"\:\;\|\=\+\*\?\<\>\/\\\,]"


def ldap_user_validator(value):
    def containsInvalidChars(s): return re.match(ldap_user_pattern, s) != None
    return not containsInvalidChars(value)


class UserSerializer(serializers.ModelSerializer):
    passwordConfirm = serializers.CharField(required=False)

    class Meta:
        model = User
        fields = (
            "username",
            "first_name",
			"last_name",
			"email",
            "password",
            "passwordConfirm"
		)

    def validate_password_confirm(self, data=None, raise_exc=True):
        if data is None and not hasattr(self, "data"):
            return False
        elif data is None:
            data = self.data
        for field in ("password", "passwordConfirm"):
            if not field in data:
                if raise_exc is True:
                    raise serializers.ValidationError(f"{field} is required.")
                else:
                    return False
        _pwd: str = data["password"]
        _pwd_confirm: str = data.pop("passwordConfirm")
        if _pwd != _pwd_confirm:
            if raise_exc is True:
                raise serializers.ValidationError("Passwords do not match.")
            else:
                return False
        return True
