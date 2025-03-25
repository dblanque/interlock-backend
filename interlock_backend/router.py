from rest_framework.routers import DefaultRouter
from rest_framework.routers import DynamicRoute


class ExplicitRouter(DefaultRouter):
	"""
	Router that only exposes endpoints explicitly decorated with @action.
	Doesn't automatically create list/create/retrieve/update/destroy endpoints.
	"""

	routes = [
		# Detail route (for methods with detail=True)
		DynamicRoute(
			url=r"^{prefix}/{lookup}/{url_path}{trailing_slash}$",
			name="{basename}-{url_name}",
			detail=True,
			initkwargs={},
		),
		# List route (for methods with detail=False)
		DynamicRoute(
			url=r"^{prefix}/{url_path}{trailing_slash}$",
			name="{basename}-{url_name}",
			detail=False,
			initkwargs={},
		),
	]

	def get_routes(self, viewset):
		"""
		Only include routes for methods decorated with @action
		"""
		routes = []

		# Get all @action decorated methods from the viewset
		for methodname in dir(viewset):
			method = getattr(viewset, methodname)
			if hasattr(method, "bind_to_methods"):
				for http_method in method.bind_to_methods:
					route_config = {
						"url_path": method.url_path if hasattr(method, "url_path") else methodname,
						"url_name": method.url_name if hasattr(method, "url_name") else methodname,
						"detail": method.detail if hasattr(method, "detail") else False,
						"methods": method.bind_to_methods,
					}
					if route_config["detail"]:
						route = DynamicRoute(
							url=r"^{prefix}/{lookup}/%s{trailing_slash}$"
							% route_config["url_path"],
							name="{basename}-%s" % route_config["url_name"],
							detail=True,
							initkwargs={},
						)
					else:
						route = DynamicRoute(
							url=r"^{prefix}/%s{trailing_slash}$" % route_config["url_path"],
							name="{basename}-%s" % route_config["url_name"],
							detail=False,
							initkwargs={},
						)
					routes.append(route)

		return routes
