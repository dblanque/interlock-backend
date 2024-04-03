################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.base
# Contains the Base Model and Base Manager
#
#---------------------------------- IMPORTS -----------------------------------#
from django.db import models
from django.db.models.manager import BaseManager as Manager
from django.db.models.query import QuerySet
from django.utils import timezone as tz
from django.utils.translation import gettext_lazy as _
################################################################################

class BaseManager(Manager.from_queryset(QuerySet)):
    use_in_migrations = False

    def get_queryset(self):
        # return super().get_queryset().all().exclude(deleted=True)
        return super().get_queryset().all()

class BaseModel(models.Model):

    created_at = models.DateTimeField(_("created at"), auto_now_add=True)
    modified_at = models.DateTimeField(_("modified at"), auto_now=True)
    deleted_at = models.DateTimeField(_("deleted at"), null=True, blank=True)
    deleted = models.BooleanField(_("deleted"), default=False)

    notes = models.TextField(blank=True, null=True)
    objects = BaseManager()
    all_objects = Manager()

    def delete(self, using=None, keep_parents=False):
        self.deleted_at = tz.now()
        self.deleted = True
        self.save(update_fields=["deleted_at", "deleted"])

    def delete_permanently(self, using=None, keep_parents=False):
        """
        Normally use delete instead of this.
        :param using:
        :param keep_parents:
        :return:
        """
        return super().delete(using=using, keep_parents=keep_parents)

    def __str__(self):
        if hasattr(self, 'name'):
            return self.name
        return super(BaseModel, self).__str__()

    class Meta:
        abstract = True
