import sys

def ignore_reverse(apps, schema_editor):  # pragma: no cover
	return

def is_in_migration():
	_manage_idx = 0
	for _, arg in enumerate(sys.argv):
		if "manage.py" in arg:
			_manage_idx = _

	return any(
		x in sys.argv[_manage_idx+1] for x in ("migrate", "makemigrations")
	)