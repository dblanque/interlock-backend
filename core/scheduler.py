from apscheduler.schedulers.background import BackgroundScheduler
from django_apscheduler.jobstores import DjangoJobStore
from core.models.ldap_ref import LdapRef
from core.ldap.connector import LDAPConnector
from core.decorators.intercept import is_ldap_backend_enabled
from django.conf import settings

def check_ldap_refs():
	if not is_ldap_backend_enabled():
		return

	with LDAPConnector(force_admin=True) as ldc:
		if not ldc.connection:
			return
		for ldap_ref in LdapRef.objects.all():
			if not isinstance(ldap_ref, LdapRef):
				continue
			ldap_ref.refresh_or_prune(connection=ldc.connection)

def start_scheduler():
	if not getattr(settings, "SCHEDULER_LDAP_REF_ENABLE", False):
		return
	scheduler = BackgroundScheduler()
	scheduler.add_jobstore(DjangoJobStore(), "default")

	interval = getattr(
		settings,
		"SCHEDULER_LDAP_REF_INTERVAL",
		{"minutes": 30}
	)
	scheduler.add_job(
		check_ldap_refs,
		"interval",
		name="LDAP Reference Consistency Checker",
		id="LdapRefConsistencyJob",
		max_instances=1,
		replace_existing=True,
		**interval
	)
	scheduler.start()
