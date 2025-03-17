from rest_framework import viewsets


class BaseViewSet(viewsets.ViewSet):
	class Meta:
		abstract = True
