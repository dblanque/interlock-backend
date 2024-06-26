# Generated by Django 4.2.4 on 2024-03-26 21:30
# For versions prior to 0.94.3
import os
from django.db import migrations
from ast import literal_eval
from interlock_backend.settings import BASE_DIR
from core.models.ldap_settings import CMAPS
import logging

NEWLINE="\n"
logger = logging.getLogger(__name__)
constants_cache_path = f"{BASE_DIR}/interlock_backend/ldap/constants_cache.py"

CC_HEADER = """# This file is generated automatically by Interlock when saving settings
# Manual changes to it might be lost
################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: constants_cache.py
# Contains the latest setting constants for Interlock

#---------------------------------- IMPORTS -----------------------------------#
from interlock_backend.ldap.constants import *
import ssl
################################################################################
"""

def cache_to_db(apps, schema_editor):
	if not os.path.isfile(constants_cache_path): return
	LDAPPreset = apps.get_model('core', 'LDAPPreset')
	LDAPSetting = apps.get_model('core', 'LDAPSetting')
	active_preset = LDAPPreset.objects.get(active=True)
	with open(constants_cache_path) as cc_file:
		for line in cc_file:
			lds = None
			v_field = None
			line = line.strip()
			if line.startswith("#"): continue
			if "interlock_backend.ldap.constants" in line: continue
			if "import ssl" in line: continue
			line = line.split("=",1)
			key = line[0].strip()
			if not key in CMAPS: continue
			else:
				v_type = CMAPS[key]
				v_field = f"v_{CMAPS[key].lower()}"
			val = line[-1].strip('"').strip("'")
			if key == "LDAP_AUTH_TLS_VERSION" and val.startswith("ssl."):
				val = str(val).split('.')[-1]
			try: val = literal_eval(val)
			except: pass
			try:
				LDAPSetting.objects.create(**{
					"name": key,
					"type": v_type,
					v_field: val,
					"preset": active_preset
				})
			except Exception as e:
				logger.exception(e)
				raise
	try: os.remove(constants_cache_path)
	except Exception as e:
		logger.exception(e)
		raise
	
def db_to_cache(apps, schema_editor):
	if os.path.isfile(constants_cache_path): return
	LDAPPreset = apps.get_model('core', 'LDAPPreset')
	LDAPSetting = apps.get_model('core', 'LDAPSetting')
	active_preset = LDAPPreset.objects.get(active=True)
	ldap_settings = LDAPSetting.objects.filter(preset_id=active_preset.id)
	with open(constants_cache_path, "w") as cc_file:
		cc_file.write(CC_HEADER + NEWLINE)
		for lds in ldap_settings:
			v_field = f"v_{CMAPS[lds.name].lower()}"
			v = getattr(lds, v_field)
			if type(v) == str: v = f'"{v}"'
			cc_file.write(f"{lds.name}={v}{NEWLINE}")
			lds.delete()
	return

class Migration(migrations.Migration):

	dependencies = [
		('core', '0004_ldappreset_defaults'),
	]

	operations = [
		migrations.RunPython(cache_to_db, db_to_cache)
	]
