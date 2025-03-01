from core.models.user import User
from core.models.ldap_settings_runtime import RunningSettings
from core.models.ldap_object import LDAPObject, LDAPObjectOptions
from oidc_provider.lib.claims import ScopeClaims, STANDARD_CLAIMS
from core.views.mixins.user import UserViewLDAPMixin
from interlock_backend.ldap.connector import LDAPConnector
from interlock_backend.ldap.adsi import search_filter_add

def get_user_groups(user: User) -> list:
    if user.is_local:
        return user.groups.values_list('name', flat=True)
    else:
        return user.ldap_groups

class CustomScopeClaims(ScopeClaims, UserViewLDAPMixin):
    def setup(self):
        # Define which claims are included for each scope
        self.claims = {
            'profile': {
                'sub': 'Username',
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

    def create_response_dic(self):
        # Fetch user data based on the requested scopes
        response_dic = super().create_response_dic()
        self.user: User

        if 'profile' in self.scopes:
            response_dic['username'] = self.user.username
            response_dic['email'] = self.user.email
            response_dic['groups'] = get_user_groups(self.user)

        if 'email' in self.scopes:
            response_dic['email'] = self.user.email

        if 'groups' in self.scopes:
            response_dic['groups'] = get_user_groups()

        return response_dic

def userinfo(claims: CustomScopeClaims, user: User):
    # Fetch user details from LDAP or your database
    for k in STANDARD_CLAIMS:
        if hasattr(user, k):
            claims[k] = getattr(user, k)
    claims['sub'] = user.username  # Subject identifier
    claims['preferred_username'] = user.username  # Subject identifier
    claims['username'] = user.username  # Subject identifier
    claims['groups'] = get_user_groups(user)
    return claims
