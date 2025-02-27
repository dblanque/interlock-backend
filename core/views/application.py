################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.application
# Contains the ViewSet for SSO Application related operations

#---------------------------------- IMPORTS -----------------------------------#
### ViewSets
from core.views.base import BaseViewSet

### Mixins
from .mixins.application import ApplicationViewMixin

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

### Others
from core.decorators.login import auth_required
import logging
################################################################################
logger = logging.getLogger(__name__)

class ApplicationViewSet(BaseViewSet, ApplicationViewMixin):
	pass