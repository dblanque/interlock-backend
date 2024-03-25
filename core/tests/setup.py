# app/tests/test_setup.py

from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from core.models.user import User
from rest_framework.test import APIClient
from core.views.mixins.settings_mixin import test_ldap_connection
from interlock_backend.ldap.constants_cache import *
from core.exceptions import ldap as exc_ldap
from interlock_backend.ldap.connector import LDAPConnector
from core.views.mixins.user import UserViewLDAPMixin

TEST_USERNAME = "testuser"
TEST_EMAIL = "testuser@example.com"
TEST_PASSWORD = "Test1234"
class TestModel(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user_mixin = UserViewLDAPMixin()
        token_url = reverse('token')
        refresh_token_url = reverse('refresh')

        # Open LDAP Connection
        try:
            c = test_ldap_connection(
                username = "admin",
                user_dn = LDAP_AUTH_CONNECTION_USER_DN,
                password = LDAP_AUTH_CONNECTION_PASSWORD,
                ldapAuthConnectionUser = LDAP_AUTH_CONNECTION_USER_DN,
                ldapAuthConnectionPassword = LDAP_AUTH_CONNECTION_PASSWORD,
                ldapAuthURL = LDAP_AUTH_URL,
                ldapAuthConnectTimeout = LDAP_AUTH_CONNECT_TIMEOUT,
                ldapAuthReceiveTimeout = LDAP_AUTH_RECEIVE_TIMEOUT,
                ldapAuthUseSSL = LDAP_AUTH_USE_SSL,
                ldapAuthUseTLS = LDAP_AUTH_USE_TLS,
                ldapAuthTLSVersion = LDAP_AUTH_TLS_VERSION,
                )
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

        # # Open LDAP Connection
        # with LDAPConnector(force_admin=True) as ldc:
        #     self.ldap_connection = ldc.connection
        #     try:
        #         UserViewLDAPMixin.ldap_user_exists(self, user_search=user_search)
        #         if LDAP_AUTH_USER_FIELDS["email"] in data and len(data[LDAP_AUTH_USER_FIELDS["email"]]) > 0:
        #             UserViewLDAPMixin.ldap_user_with_email_exists(self, email_search=data[LDAP_AUTH_USER_FIELDS["email"]])
        #         user_dn = UserViewLDAPMixin.ldap_user_insert(user_data=data)
        #         user_pwd = data['password']
        #         UserViewLDAPMixin.set_ldap_password(self, user_dn=user_dn, user_pwd=user_pwd)
        #     except:
        #         raise
        # u = User.objects.create_user(username=TEST_USERNAME, email=TEST_EMAIL, password=TEST_PASSWORD)
        # u.is_active = False
        # u.save()

        # resp = self.client.post(url, {'email':'user@foo.com', 'password':'pass'}, format='json')
        # self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

        # u.is_active = True
        # u.save()

        # resp = self.client.post(url, {'username':'user@foo.com', 'password':'pass'}, format='json')
        # self.assertEqual(resp.status_code, status.HTTP_200_OK)
        # self.assertTrue('token' in resp.data)
        # token = resp.data['token']
        # #print(token)

        # verification_url = reverse('api-jwt-verify')
        # resp = self.client.post(verification_url, {'token': token}, format='json')
        # self.assertEqual(resp.status_code, status.HTTP_200_OK)

        # resp = self.client.post(verification_url, {'token': 'abc'}, format='json')
        # self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

        # client = APIClient()
        # client.credentials(HTTP_AUTHORIZATION='JWT ' + 'abc')
        # resp = client.get('/api/v1/account/', data={'format': 'json'})
        # self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)
        # client.credentials(HTTP_AUTHORIZATION='JWT ' + token)
        # resp = client.get('/api/v1/account/', data={'format': 'json'})
        # self.assertEqual(resp.status_code, status.HTTP_200_OK)