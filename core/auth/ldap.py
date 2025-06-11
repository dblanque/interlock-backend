################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: interlock_backend.ldap.auth

# ---------------------------------- IMPORTS --------------------------------- #
from django.contrib.auth.backends import ModelBackend
import core.ldap.connector as ldap

################################################################################
"""
Django authentication backend.
"""


class LDAPBackend(ModelBackend):
	"""
	An authentication backend that delegates to an LDAP
	server.

	User models authenticated with LDAP are created on
	the fly, and syncronised with the LDAP credentials.
	"""

	supports_inactive_user = False

	def authenticate(self, *args, **kwargs):
		return ldap.authenticate(*args, **kwargs)
