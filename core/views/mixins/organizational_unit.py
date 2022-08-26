################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU GPLv3 #####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.organizational_unit
# Contains the Mixin for Organizational Unit related operations

#---------------------------------- IMPORTS -----------------------------------#
### ViewSets
from rest_framework import viewsets

### Interlock
from interlock_backend.ldap.adsi import addSearchFilter, buildFilterFromDict
from interlock_backend.ldap.constants_cache import *

### Others
import logging
################################################################################

logger = logging.getLogger(__name__)
class OrganizationalUnitMixin(viewsets.ViewSetMixin):
    def processFilter(self, data, filterDict=None):
        ldapFilter = ""

        if 'filter' in data and 'iexact' in data['filter']:
            logger.debug("Dirtree fetching with Filter iexact")
            if len(data['filter']['iexact']) > 0:
                for f in data['filter']['iexact']:
                    fVal = data['filter']['iexact'][f]
                    if isinstance(fVal, dict):
                        fType = fVal.pop('attr')
                        if 'exclude' in fVal:
                            fExclude = fVal.pop('exclude')
                        else:
                            fExclude = False
                        if 'or' in fVal:
                            fOr = fVal.pop('or')
                        else:
                            fOr = False

                        if fOr == True:
                            operator = "|"
                        else:
                            operator = "&"
                        ldapFilter = addSearchFilter(ldapFilter, fType + "=" + f, operator=operator, negate=fExclude)
                    else:
                        fType = fVal
                        ldapFilter = addSearchFilter(ldapFilter, fType + "=" + f)
        else:
            logger.debug("Dirtree fetching with Standard Exclusion Filter")
            if filterDict is None:
                filterDict = {**LDAP_DIRTREE_CN_FILTER, **LDAP_DIRTREE_OU_FILTER}
            if 'filter' in data and 'exclude' in data['filter']:
                if len(data['filter']['exclude']) > 0:
                    for f in data['filter']['exclude']:
                        fType = data['filter']['exclude'][f]
                        if f in filterDict:
                            del filterDict[f]

            ldapFilter = buildFilterFromDict(filterDict)

            # Where f is Filter Value, fType is the filter Type (not a Jaguar)
            # Example: objectClass=computer
            # f = computer
            # fType = objectClass
            if 'filter' in data and 'exclude' in data['filter']:
                if len(data['filter']['exclude']) > 0:
                    for f in data['filter']['exclude']:
                        fType = data['filter']['exclude'][f]
                        ldapFilter = addSearchFilter(ldapFilter, fType + "=" + f, negate=True)

        logger.debug("LDAP Filter for Dirtree: ")
        logger.debug(ldapFilter)

        return ldapFilter
