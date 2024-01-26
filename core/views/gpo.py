################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.gpo
# Contains the ViewSet for Group Policy Object related operations

# Work in Progress
# src: https://github.com/samba-team/samba/blob/master/python/samba/netcmd/gpo.py
#---------------------------------- IMPORTS -----------------------------------#
### ViewSets
from .base import BaseViewSet

import logging
################################################################################

logger = logging.getLogger(__name__)

class GPOViewSet(BaseViewSet):
	pass