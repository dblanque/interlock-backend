from interlock_backend.ldap.defaults import *
from interlock_backend.ldap import defaults
from .ldap_settings import CMAPS, LDAPSetting
from django.db import connection
import sys
this_module = sys.modules[__name__]

# For constant, value_type in...
for c, value_type in CMAPS.items():
	s = None
	all_tables = connection.introspection.table_names()
	if "core_ldapsetting" in all_tables:
		# Setting
		s = LDAPSetting.objects.filter(name=c)
		if s.exists():
			s = s[0]
	# Default
	d = getattr(defaults, c)
	# Value
	v = getattr(s, f"v_{value_type.lower()}", d)
	setattr(this_module, c, v)
