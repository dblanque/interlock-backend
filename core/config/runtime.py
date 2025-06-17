################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.config.runtime
# Contains the RuntimeSettingsSingleton global instance.

# ---------------------------------- IMPORTS -----------------------------------#
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
################################################################################

RuntimeSettings = RuntimeSettingsSingleton()
