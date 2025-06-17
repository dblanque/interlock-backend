################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.serializers.application_group
# Contains the Application Security Group Serializer

#---------------------------------- IMPORTS -----------------------------------#
from rest_framework import serializers
from core.models.application import ApplicationSecurityGroup
################################################################################


class ApplicationSecurityGroupSerializer(serializers.ModelSerializer):
	class Meta:
		model = ApplicationSecurityGroup
		fields = "__all__"
