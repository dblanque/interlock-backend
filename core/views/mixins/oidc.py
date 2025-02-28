from core.models.user import User
from core.models.ldap_settings_runtime import RunningSettings
from core.models.ldap_object import LDAPObject, LDAPObjectOptions
from django.utils.translation import ugettext_lazy as _
from oidc_provider.lib.claims import ScopeClaims
from core.views.mixins.user import UserViewLDAPMixin
from interlock_backend.ldap.connector import LDAPConnector
from interlock_backend.ldap.adsi import search_filter_add

class CustomScopeClaims(ScopeClaims, UserViewLDAPMixin):
    def setup(self):
        # Define which claims are included for each scope
        self.claims = {
            'profile': {
                'username': 'Username',
                'email': 'Email',
                'groups': 'Groups',
            },
            'email': {
                'email': 'Email',
            },
            'groups': {
                'groups': 'Groups',
            },
        }
    
    def get_user_groups(self) -> list:
        if self.user.is_local:
            return list(self.user.groups.values_list('name', flat=True))
        else:
            # Open LDAP Connection
            with LDAPConnector(self.user.dn, self.user.encryptedPassword, self.user.username) as ldc:
                self.ldap_connection = ldc.connection
                self.ldap_filter_attr = [
                    "memberOf"
                ]

                # Add filter for username
                self.ldap_filter_object = search_filter_add(
                    self.ldap_filter_object,
                    f"{RunningSettings.LDAP_AUTH_USER_FIELDS['username']}={self.user.username}"
                )
                ldap_object_options: LDAPObjectOptions = {
                    "connection": self.ldap_connection,
                    "ldapFilter": self.ldap_filter_object,
                    "ldapAttributes": self.ldap_filter_attr,
                }

                user_obj = LDAPObject(**ldap_object_options)
                user_entry = user_obj.entry
                user_dict = user_obj.attributes

                return list(user_dict["memberOf"])

    def create_response_dic(self):
        # Fetch user data based on the requested scopes
        response_dic = super().create_response_dic()
        self.user: User

        if 'profile' in self.scopes:
            response_dic['username'] = self.user.username
            response_dic['email'] = self.user.email
            response_dic['groups'] = self.get_user_groups()

        if 'email' in self.scopes:
            response_dic['email'] = self.user.email

        if 'groups' in self.scopes:
            response_dic['groups'] = self.get_user_groups()

        return response_dic

def userinfo(claims, user: User):
    # Fetch user details from LDAP or your database
    claims['sub'] = user.username  # Subject identifier
    claims['email'] = user.email
    # TODO - Fetch current User LDAP Groups
    claims['groups'] = list(user.ldap_groups.values_list('name', flat=True))
    return claims
