################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.log
# Contains the Model for Log Entries
#
# ---------------------------------- IMPORTS --------------------------------- #
### Django
from django.utils.translation import gettext_lazy as _
from django.db.models.manager import BaseManager as Manager
from django.db import models

### Base
from core.models.base import BaseManager

### Choices
from core.models.choices.log import ACTION_CHOICES, CLASS_CHOICES


# ---------------------------------------------------------------------------- #
class BaseLogModel(models.Model):
	logged_at = models.DateTimeField(_("logged at"), auto_now_add=True)
	rotated = models.BooleanField(_("rotated"), default=False)

	notes = models.TextField(blank=True, null=True)
	objects = BaseManager()
	all_objects = Manager()

	class Meta:
		abstract = True


class Log(BaseLogModel):
	user = models.ForeignKey("User", on_delete=models.CASCADE)
	operation_type = models.CharField(
		_("operation_type"),
		choices=ACTION_CHOICES,
		max_length=256,
		null=False,
		blank=False,
	)
	log_target_class = models.CharField(
		_("log_target_class"),
		choices=CLASS_CHOICES,
		max_length=256,
		null=False,
		blank=False,
	)
	log_target = models.JSONField(_("log_target"), null=True, blank=True)
	message = models.CharField(
		_("message"), max_length=256, null=True, blank=True
	)

	def __str__(self):
		return f"log_{self.id}_{self.operation_type.lower()}_{self.log_target_class.lower()}"
