from interlock_backend.ldap.defaults import *
from .ldap_settings import CMAPS, LDAPSetting, LDAPPreset
from django.db import connection
import sys
this_module = sys.modules[__name__]

all_tables = connection.introspection.table_names()
active_preset = None
if "core_ldappreset" in all_tables:
	active_preset = LDAPPreset.objects.get(active=True)

# For constant, value_type in...
for c, value_type in CMAPS.items():
	s = None
	if "core_ldapsetting" in all_tables:
		# Setting
		s = LDAPSetting.objects.filter(name=c, preset_id=active_preset)
		if s.exists():
			s = s[0]
	# Default
	d = getattr(this_module, c)
	# Value
	v = getattr(s, f"v_{value_type.lower()}", d)
	setattr(this_module, c, v)
