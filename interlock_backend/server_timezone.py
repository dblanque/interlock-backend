################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: interlock_backend.server_timezone
# Contains utilities to fetch local timezone from the server

# ---------------------------------- IMPORTS -----------------------------------#
import os
import pytz
import subprocess
from logging import getLogger
################################################################################

logger = getLogger()

# Local Time Path
_LTP = "/etc/localtime"


def get_server_timezone():
	"""Gets server localtime timezone."""
	time_zone = None
	try:
		# timedatectl (most Linux systems)
		time_zone = (
			subprocess.check_output(
				"timedatectl show --property=Timezone --value".split(),
				stderr=subprocess.DEVNULL,
			)
			.decode()
			.strip()
		)
	except:
		# Linux / macOS only (Windows unsupported)
		try:
			time_zone_path = os.path.realpath(_LTP)
			if "zoneinfo" in time_zone_path:
				time_zone = time_zone_path.split("zoneinfo/")[-1]
			else:
				time_zone = "/".join(time_zone_path.split("/")[-2:])
		except:
			# Fallback to UTC
			time_zone = "UTC"
			pass

	# Validate the timezone exists in pytz
	if time_zone not in pytz.all_timezones:
		logger.warning(
			f"Warning: Detected timezone '{time_zone}' is invalid. "
			"Falling back to UTC."
		)
		time_zone = "UTC"

	logger.info(f"Configured timezone: {time_zone}")
	return time_zone
