# core.utils.iterables


def flatten_list(lst: list[list]) -> list:
	return [i for sub in lst for i in sub]


def recursive_dict_find(obj, key):
	if key in obj:
		return obj[key]
	for k, v in obj.items():
		if isinstance(v, dict):
			item = recursive_dict_find(v, key)
			if item is not None:
				return item


def is_non_str_iterable(v):
	"""Checks if value is within types (tuple, list, set, dict)

	Args:
		v (tuple or list or set or dict): Some value to check.

	Returns:
		bool
	"""
	if isinstance(v, str):
		return False
	return isinstance(v, (tuple, list, set, dict))
