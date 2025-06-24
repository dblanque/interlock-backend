################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.serializers.oidc
# Contains the OIDC Client Serializer class

# ---------------------------------- IMPORTS --------------------------------- #
from rest_framework import serializers
from oidc_provider.models import Client
################################################################################


class ClientSerializer(serializers.ModelSerializer):
	class Meta:
		model = Client
		fields = "__all__"
