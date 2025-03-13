from core.models.interlock_settings import (
	InterlockSetting,
	INTERLOCK_SETTING_ENABLE_LDAP,
	INTERLOCK_SETTING_MAP,
	INTERLOCK_SETTING_TABLE
)
from core.utils.db import db_table_exists

DEFAULT_FIXTURE = {
	INTERLOCK_SETTING_ENABLE_LDAP: False
}

def create_default_interlock_settings():
	if not db_table_exists(INTERLOCK_SETTING_TABLE):
		return
	for setting_key, setting_type in INTERLOCK_SETTING_MAP.items():
		if not setting_key in DEFAULT_FIXTURE:
			continue
		if InterlockSetting.objects.filter(name=setting_key).count() > 0:
			continue
		InterlockSetting.objects.create(
			name=setting_key,
			type=setting_type,
			value=DEFAULT_FIXTURE[setting_key]
		)