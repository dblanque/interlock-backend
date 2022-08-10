################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU GPLv3 #####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.token
# Contains the ViewSet for Token Authentication related operations

#---------------------------------- IMPORTS -----------------------------------#
from rest_framework_simplejwt import views as jwt_views
from core.serializers.token import (
    TokenObtainPairSerializer,
    TokenRefreshSerializer
)
################################################################################

class TokenObtainPairView(jwt_views.TokenViewBase):
    """
    Takes a set of user credentials and returns an access and refresh JSON web
    token pair to prove the authentication of those credentials.
    """
    serializer_class = TokenObtainPairSerializer

token_obtain_pair = TokenObtainPairView.as_view()

class TokenRefreshView(jwt_views.TokenViewBase):
    """
    Takes a refresh type JSON web token and returns an access type JSON web
    token if the refresh token is valid.
    """
    serializer_class = TokenRefreshSerializer

token_refresh = TokenRefreshView.as_view()