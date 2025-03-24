def get_ids_for_cases(argnames: tuple[str], cases: tuple[tuple]):
	"""
	Returns a tuple of comma separated argnames and values for each case.
	("a=1,b=2", "a=3,b=4")
	(("a=1","b=2"),("a=3","b=4"),)
	"""
	r = []
	if isinstance(argnames, str):
		argnames = argnames.split(",")
	for case in cases:
		case_ids = []
		for arg, val in zip(argnames, case):
			case_ids.append(f"{arg.strip()}: {str(val)}")
		r.append(str(case_ids))
	return tuple(r)
