import dns.asyncbackend
import dns.asyncquery
import dns.asyncresolver
import dns.dnssec
import dns.e164
import dns.edns
import dns.entropy
import dns.exception
import dns.flags
import dns.immutable
import dns.inet
import dns.ipv4
import dns.ipv6
import dns.message
import dns.name
import dns.namedict
import dns.node
import dns.opcode
import dns.query
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.renderer
import dns.resolver
import dns.reversename
import dns.rrset
import dns.serial
import dns.set
import dns.tokenizer
import dns.transaction
import dns.tsig
import dns.tsigkeyring
import dns.ttl
import dns.rdtypes
import dns.update
import dns.version
import dns.versioned
import dns.wire
import dns.xfr
import dns.zone
import dns.zonefile
import ipaddress


def getDNSResolver(dnsAddresses):
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
