import subprocess
from os.path import isfile

'''
This file contains the definitions used by SoapySDR
'''
SOAPY_AVAILABLE = False

try:
    import SoapySDR
    from SoapySDR import *
    SOAPY_AVAILABLE = True
except:
    pass
