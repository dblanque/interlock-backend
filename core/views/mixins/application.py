################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.application
# Contains the mixin for SSO Application related operations

#---------------------------------- IMPORTS -----------------------------------#
### ViewSets
from rest_framework import viewsets

### Others
import logging
################################################################################
logger = logging.getLogger()

class ApplicationViewMixin(viewsets.ViewSetMixin):
	pass