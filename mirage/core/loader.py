from mirage.libs import io

class Loader:
	'''
	This class permits to dynamically load the modules.
	'''
	def __init__(self):
		'''
		This constructor generates the modules list.
		'''
		import mirage.modules as modules
		self.modulesList = {}
		#for moduleName,module in modules.__modules__.items():
		for moduleName in modules.moduleNames:
			#current = module#__import__("modules."+module, fromlist=module)
			#moduleClass = getattr(current,moduleName)
			self.modulesList[moduleName] = None#moduleClass

	def getModulesNames(self):
		'''
		This method returns a list of existing modules' names.

		:return: list of modules' name
		:rtype: list of str
		'''
		return list(self.modulesList.keys())

	def load(self,moduleName):
		'''
		This method returns an instance of a specific module according to the name provided as parameter.

		:param moduleName: name of a module
		:type moduleName: str
		:return: an instance of the module
		:rtype: core.module.Module
		'''
		if moduleName in self.modulesList:
			if self.modulesList[moduleName] is None:
				tmp_import=__import__("mirage.modules",fromlist=[moduleName])
				tmp_module=getattr(tmp_import,moduleName)
				self.modulesList[moduleName]=getattr(tmp_module,moduleName)
			return self.modulesList[moduleName]()
		else:
			return None


	def list(self,pattern=""):
		'''
		Display the list of module, filtered by the string provided as ``pattern``.

		:param pattern: filter
		:type pattern: str
		'''
		displayDict = {}

		for module in self.modulesList:
			if self.modulesList[module] is None:
				#tmp_import=__import__("mirage.modules."+module,fromlist=[module])
				tmp_import=__import__("mirage.modules",fromlist=[module])
				tmp_module=getattr(tmp_import,module)
				self.modulesList[module]=getattr(tmp_module,module)
			info = self.modulesList[module]().info()
			technology = (info["technology"][:1]).upper() + (info["technology"][1:]).lower()
			if (
				pattern in info["description"]	or
				pattern in info["name"] 	or
				pattern in info["technology"]	or
				pattern in info["type"]
			):
				if not technology in displayDict:
					displayDict[technology] = []
				displayDict[technology].append([info["name"], info["type"], info["description"]])


		for module in sorted(displayDict):
			if displayDict[module]:
				io.chart(["Name", "Type","Description"], sorted(displayDict[module]), "{} Modules".format(module))
