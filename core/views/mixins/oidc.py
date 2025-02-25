from core.models.user import User
from django.utils.translation import ugettext_lazy as _
from oidc_provider.lib.claims import ScopeClaims

class CustomScopeClaims(ScopeClaims):
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

    def create_response_dic(self):
        # Fetch user data based on the requested scopes
        response_dic = super().create_response_dic()
        self.user: User

        if 'profile' in self.scopes:
            response_dic['username'] = self.user.username
            response_dic['email'] = self.user.email
            response_dic['groups'] = list(self.user.ldap_groups)

        if 'email' in self.scopes:
            response_dic['email'] = self.user.email

        if 'groups' in self.scopes:
            response_dic['groups'] = list(self.user.ldap_groups)

        return response_dic

def userinfo(claims, user: User):
    # Fetch user details from LDAP or your database
    claims['sub'] = user.username  # Subject identifier
    claims['email'] = user.email
    claims['groups'] = list(user.ldap_groups.values_list('name', flat=True))  # Fetch groups from LDAP
    return claims
