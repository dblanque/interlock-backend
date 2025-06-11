# Module: core.utils.csv
import csv
from rest_framework.generics import QuerySet

class PseudoBuffer:
	def write(self, value):
		return value

def csv_iterator(queryset: list[dict] | QuerySet, fields):
	pseudo_buffer = PseudoBuffer()
	writer = csv.DictWriter(pseudo_buffer, fieldnames=fields)
	yield writer.writeheader()

	# If its a list of dictionaries
	if isinstance(queryset, list):
		for item in queryset:
			if not isinstance(item, dict):
				raise TypeError("item in list should be a dictionary")
			yield writer.writerow(item)
	# If its a django queryset
	elif isinstance(queryset, QuerySet):
		for item in queryset.values(*fields):
			yield writer.writerow(item)
