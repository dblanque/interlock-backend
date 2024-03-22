################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.organizational_unit
# Contains the Mixin for Organizational Unit related operations

#---------------------------------- IMPORTS -----------------------------------#
### ViewSets
from rest_framework import viewsets

### Exceptions
from core.exceptions import dirtree as exc_dirtree

### Interlock
from interlock_backend.ldap.adsi import search_filter_add, search_filter_from_dict
from interlock_backend.ldap.constants_cache import *

### Models
from core.models.log import logToDB

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
                        ldapFilter = search_filter_add(ldapFilter, fType + "=" + f, operator=operator, negate=fExclude)
                    else:
                        fType = fVal
                        ldapFilter = search_filter_add(ldapFilter, fType + "=" + f)
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

            ldapFilter = search_filter_from_dict(filterDict)

            # Where f is Filter Value, fType is the filter Type (not a Jaguar)
            # Example: objectClass=computer
            # f = computer
            # fType = objectClass
            if 'filter' in data and 'exclude' in data['filter']:
                if len(data['filter']['exclude']) > 0:
                    for f in data['filter']['exclude']:
                        fType = data['filter']['exclude'][f]
                        ldapFilter = search_filter_add(ldapFilter, fType + "=" + f, negate=True)

        logger.debug("LDAP Filter for Dirtree: ")
        logger.debug(ldapFilter)

        return ldapFilter
    
    def move_or_rename_object(self, distinguished_name:str, relative_dn:str=None, ldap_path:str=None) -> str:
        """
        * relative_dn = Will rename the object if changed from what is in distinguished_name
        * ldap_path = Will relocate object if changed from what is in distinguished_name
        Returns new object Distinguished Name
        """
        operation = "RENAME"
        new_dn = None
        if relative_dn:
            new_relative_dn = relative_dn
        else:
            new_relative_dn = distinguished_name.split(",")[0]

        if new_relative_dn == distinguished_name:
            raise exc_dirtree.DirtreeDistinguishedNameConflict

        if ldap_path:
            operation = "MOVE"
        try:
            if ldap_path:
                self.ldap_connection.modify_dn(distinguished_name, new_relative_dn, new_superior=ldap_path)
                new_dn = f"{new_relative_dn},{ldap_path}"
            else:
                self.ldap_connection.modify_dn(distinguished_name, new_relative_dn)
                new_path = distinguished_name.split(",")
                del new_path[0]
                new_path = ",".join(new_path)
                new_dn = f"{new_relative_dn},{new_path}"
        except Exception as e:
            print(e)
            data = {
                "ldap_response": self.ldap_connection.result,
                "ldapObject": new_relative_dn,
            }
            if hasattr(self.ldap_connection.result, "description"):
                if self.ldap_connection.result.description == "entryAlreadyExists":
                    data['code'] = 409
            self.ldap_connection.unbind()
            raise exc_dirtree.DirtreeMove(data=data)

        if LDAP_LOG_UPDATE == True:
            # Log this action to DB
            logToDB(
                user_id=self.request.user.id,
                actionType="UPDATE",
                objectClass="LDAP",
                affectedObject=new_relative_dn,
                extraMessage=operation
            )
        return new_dn
