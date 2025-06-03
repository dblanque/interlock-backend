import dns.resolver
import ipaddress


def get_dns_resolver(dnsAddresses):
	# Set Query for IP Address
	if dnsAddresses is None:
		raise ValueError("You need a Server Address to query")
	elif not isinstance(dnsAddresses, list) and not isinstance(
		dnsAddresses, str
	):
		raise ValueError("dnsAddresses can only be a list or string value")
	else:
		# Create Resolver Object
		resolver = dns.resolver.Resolver()

		# If it's a list loop for every address to check validity
		if isinstance(dnsAddresses, list):
			for ip in dnsAddresses:
				if not ipaddress.ip_address(ip):
					raise ValueError("An IP Address in the list is invalid")
				else:
					resolver.nameservers.append(ip)
		# If it's just one address
		else:
			if not ipaddress.ip_address(dnsAddresses):
				raise ValueError("An IP Address in the list is invalid")
			else:
				resolver.nameservers = [dnsAddresses]

	return resolver
