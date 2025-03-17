import json
import os


class ResponseHandler:
	def __get_message_for_code(code):
		# Opening JSON file
		pwd = os.path.dirname(__file__)
		f = open(pwd + "/../../config/responses.json")
		# Parses JSON object.
		data = json.load(f)
		if data == None or code not in data:
			return None
		return data[code]

	def send(message_code, detail=None):
		num_msg_dict = ResponseHandler.__get_message_for_code(message_code)
		data = {}
		if num_msg_dict == None:
			data["code"] = -1
			data["message"] = "Incorrect Configuration. Code '" + message_code + "' not found."
		else:
			data["code"] = num_msg_dict["code"]
			data["message"] = num_msg_dict["message"]
			if detail != None:
				data["detail"] = detail
		return data
