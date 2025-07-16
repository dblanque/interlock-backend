import sys

def ignore_reverse(apps, schema_editor):  # pragma: no cover
	return

def is_in_migration(
	only_migrate: bool = False,
	only_make_migrations: bool = False,
) -> bool:
	"""Function to check whether the current process was executed with
	migrate or makemigrations arguments."""
	opts = {"migrate", "makemigrations"}
	_manage_idx = 0

	for _, arg in enumerate(sys.argv):
		if "manage.py" in arg.lower():
			_manage_idx = _
	if only_make_migrations and only_migrate:
		raise ValueError(
			"only_migrate and only_make_migrations are mutually excluding "
			"options and may not be used together."
		)

	if only_migrate:
		opts.remove("makemigrations")
	elif only_make_migrations:
		opts.remove("migrate")
	return any(x.lower() in sys.argv[_manage_idx+1] for x in opts)