import os
import pytz
import subprocess

def get_server_timezone():
	time_zone = None
	try:
		# timedatectl (most Linux systems)
		time_zone = subprocess.check_output(
			'timedatectl show --property=Timezone --value'.split(), 
			stderr=subprocess.DEVNULL,
		).decode().strip()
	except:
		try:
			# Linux / macOS only (Windows unsupported)
			try:
				time_zone = os.path.realpath('/etc/localtime').split('/')[-2:][1]
			except:
				pass
		except:
			# Fallback to UTC
			time_zone = 'UTC'

	# Validate the timezone exists in pytz
	if time_zone not in pytz.all_timezones:
		print(f"Warning: Detected timezone '{time_zone}' is invalid. Falling back to UTC.")
		time_zone = 'UTC'

	print(f"Configured timezone: {time_zone}")
	return time_zone
