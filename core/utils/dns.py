import dns.resolver
import ipaddress


def get_dns_resolver(dns_addresses: list[str]):
	# Set Query for IP Address
	if not dns_addresses:
		raise ValueError("You need one or more Server Addresses to query")
	elif not isinstance(dns_addresses, list) and not isinstance(
		dns_addresses, str
	):
		raise TypeError("dns_addresses must be of type str, list[str]")
	else:
		# Create Resolver Object
		resolver = dns.resolver.Resolver()

		# If it's a list loop for every address to check validity
		if isinstance(dns_addresses, list):
			for ip in dns_addresses:
				try:
					ipaddress.ip_address(ip)
					resolver.nameservers.append(ip)
				except:
					raise ValueError(
						f"An IP Address is invalid ({str(ip)}, type: {type(ip).__name__})"
					)
		# If it's just one address
		else:
			try:
				ipaddress.ip_address(dns_addresses)
				resolver.nameservers = [dns_addresses]
			except:
				raise ValueError(
					f"Invalid IP Address ({str(dns_addresses)}, type: {type(dns_addresses).__name__})"
				)
	return resolver
