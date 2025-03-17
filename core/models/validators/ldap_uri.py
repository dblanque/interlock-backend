from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
import re

LDAP_URI_RE = r"^(ldap(s)?:\/\/)(((\d{1,3}.){3}\d{1,3}(:\d+)?)|(\w|\d|)+|((\[([a-f0-9]{1,4}:{1,2}){1,4}([a-f0-9]{1,4})\])(:\d+)?)).\w+$"


def validate_ldap_uri(value):
	for sub_v in value:
		if not re.match(LDAP_URI_RE, sub_v):
			raise ValidationError(
				_("%(value)s contains an invalid LDAP URI"),
				params={"value": value},
			)
