import subprocess

def ping(host, count=3, timeout=3, args=[]) -> int:
	"""
	Returns OS command exit code 0 if successful.
	Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.
	"""

	# Option for the number of packets as a function of
	param_p = '-c'
	param_t = '-W'

	# Building the command. Ex: "ping -c 1 google.com"
	command = ['ping', param_p, str(count), host, param_t, str(timeout)]
	if len(args) > 0:
		for a in args:
			command.append(a)

	return subprocess.call(command)
