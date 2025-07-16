import os
from genbadge import Badge
import django

FILE_PATH = os.path.dirname(os.path.realpath(__file__))
django_version = ""
for c in django.VERSION:
	if isinstance(c, int):
		django_version += f"{str(c)}."
	else:
		django_version = django_version.strip(".")
		django_version += f"-{c}"
		break

BLUE = "#396DBC"
BADGES = [
	{
		"left_txt":"docs",
		"right_txt":"latest",
		"color": BLUE,
		"name": "docs-badge"
	},
	{
		"left_txt":"django",
		"right_txt": django_version,
		"color": BLUE,
		"name": "django-version-badge"
	},
	{
		"left_txt":"official",
		"right_txt": "website",
		"color": "orange",
		"name": "website-badge"
	},
]

for badge_args in BADGES:
	name = badge_args.pop("name")
	b = Badge(**badge_args)
	b.write_to(
		os.path.join(
			FILE_PATH,
			"reports",
			"badges",
			name + ".svg"
		),
		use_shields=False
	)