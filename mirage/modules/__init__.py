import os, sys#, importlib
from mirage.core.app import App
from mirage.libs.utils import getHomeDir#,generateModulesDictionary

if App.Instance is not None:
	# Modules Directory
	MODULES_DIR = os.path.abspath(os.path.dirname(__file__))
	MODULES_USER_DIR = getHomeDir() + "/modules"
	moduleNames=[x[:-3] for x in os.listdir(MODULES_DIR) if x[-3:]==".py" and x[0]!="_"]
	#tmp_modules=__import__("mirage.modules",fromlist=moduleNames)
	#__modules__={}
	#for path in moduleNames:
	#	name=path[:-3]
	#	__modules__[name]=getattr(tmp_modules,name)

#if App.Instance is not None:
#	# Modules Directory
#	MODULES_DIR = os.path.abspath(os.path.dirname(__file__))
#	MODULES_USER_DIR = getHomeDir() + "/modules"
#
#	# Insertion of the root directory in the PYTHON PATH
#	#sys.path.insert(0,  os.path.abspath(os.path.dirname(__file__)+"/.."))
#
#	# Creation of the list of modules()
#	__modules__ = generateModulesDictionary(MODULES_DIR, MODULES_USER_DIR)
#'''
#__modules__ = {}
#
#for module in os.listdir(MODULES_DIR):
#	if os.path.isfile(MODULES_DIR+"/"+module) and module[-3:] == ".py" and module != "__init__.py":
#		__modules__[module[:-3]] = imp.load_source(module[:-3],MODULES_DIR + "/"+module)
#		
#for module in os.listdir(MODULES_USER_DIR):
#	if os.path.isfile(MODULES_USER_DIR+"/"+module) and module[-3:] == ".py" and module != "__init__.py":
#		__modules__[module[:-3]] = imp.load_source(module[:-3],MODULES_USER_DIR + "/"+module)
#'''		
#'''
#__modules__ = []
#for module in os.listdir(MODULES_DIR):
#	if os.path.isfile(MODULES_DIR+"/"+module) and module[-3:] == ".py" and module != "__init__.py":
#		__modules__.append(module[:-3])
#
#for module in os.listdir(MODULES_USER_DIR):
#	if os.path.isfile(MODULES_USER_DIR+"/"+module) and module[-3:] == ".py" and module != "__init__.py":
#		__modules__.append(module[:-3])
#		py_mod = imp.load_source(module[:-3],MODULES_USER_DIR + "/"+module)
#'''
