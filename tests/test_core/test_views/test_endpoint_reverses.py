from django.urls import reverse
import re

RE_IS_DETAIL = re.compile(r".*\-\@\-$")

def test_reverse_matches_endpoint(g_all_endpoints: tuple[str, str]):
	url, method = g_all_endpoints
	reverse_url = url\
		.format(pk="@")\
		.replace("/api/","", 1)\
		.replace("/","-")\
		.replace("ldap-","ldap/", 1)\
		.replace("application-group","application/group", 1)
	
	requires_pk = True if "@" in reverse_url else False
	is_detail = True if re.match(RE_IS_DETAIL, reverse_url) else False

	if is_detail:
		reverse_url = reverse_url.replace("-@-","-detail")
	else:
		reverse_url = reverse_url.replace("-@-","-")

	if reverse_url.endswith("-"):
		reverse_url = reverse_url[:-1]

	if requires_pk:
		assert url.format(pk=0) == reverse(reverse_url, args=(0,))
	else:
		try:
			assert url.format(pk=0) == reverse(reverse_url)
		except Exception as e:
			try:
				assert url.format(pk=0) == reverse(reverse_url + "-list")
			except:
				raise e
