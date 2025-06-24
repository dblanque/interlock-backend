from django.db import connection


def db_table_exists(table_name):
	try:
		return table_name in connection.introspection.table_names()
	except:
		return False
