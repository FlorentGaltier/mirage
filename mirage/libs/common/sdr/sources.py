from ctypes import *
from mirage.libs.common.sdr.hackrf_definitions import *
from mirage.libs.common.sdr.pipeline import *
from mirage.libs.common.sdr.hardware import *
from mirage.libs import io,utils
import os,threading,numpy

import numpy as np
import pickle

ITER_NOISE=10

'''
This component implements the supported Software Defined Radio Sources (e.g. RX).
'''

class SDRSource:
	'''
	This class defines a standard Software Defined Radio source.
	Every Software Defined Radio supporting IQ reception has to implement a Source inheriting from this class.

	The following methods have to be implemented:

		  * ``startStreaming()`` : this method allows to start the IQ streaming
		  * ``stopStreaming()`` : this method allows to stop the IQ streaming
		  * ``isStreaming()`` : this method returns a boolean indicating if streaming is enabled
		  * ``close()`` : this method closes the sink

	'''

	def __init__(self,interface):
		self.interface = interface
		self.running = False
		self.frequency = None
		self.bandwidth = None
		self.gain = None
		self.blockLength = None
		self.sampleRate = None
		self.iqStream = []

	def setBandwidth(self,bandwidth):
		self.bandwidth = bandwidth

	def setFrequency(self,frequency):
		self.frequency = frequency

	def setGain(self,gain):
		self.gain = gain

	def setSampleRate(self,sampleRate):
		self.sampleRate = sampleRate

	def isStreaming(self):
		return self.running

	def startStreaming(self):
		self.running = True

	def stopStreaming(self):
		self.running = False

	def close(self):
		if self.running:
			self.stopStreaming()

	def __rshift__(self, demodulator):
		demodulator.setSource(self)
		return SDRPipeline(source=self,demodulator=demodulator)

#class SoapySDRSource(SoapySDRHardware,SDRSource):
class SoapySDRSource(SDRSource,SoapySDRHardware):
	numberOfSources = 0

	def __del__(self):
		self.close()
		SoapySDRSource.numberOfSources-=1
		if SoapySDRSource.numberOfSources == 0:
			SoapySDRHardware.closeAPI()

	def __init__(self,interface):
		self.alreadyStarted = False
		self.loop_running=False
		self.loop_continue=False
		self.thread=None
		self.stream=None
		SDRSource.__init__(self,interface=interface)
		SoapySDRHardware.__init__(self,interface=interface)
		self.noise_amp=None

		if self.ready:
			SoapySDRSource.numberOfSources+=1

	def _runReception(self):
		import pickle
		self.loop_running=True
		self.loop_continue=True
		self.alreadyStarted=True
		iteration_num=0
		line=[]
		median_amplitudes=[]
		try:
			while self.loop_continue:
				#print("AH")
				tmp_buf=np.zeros(self.blockLength, dtype=np.complex64)
				self.lock.acquire()
				self.device.readStream(self.stream,[tmp_buf],self.blockLength,timeoutUs=1000000)
				if iteration_num<ITER_NOISE or np.max(np.abs(tmp_buf))>self.noise_amp*1.25:
					self.iqStream+=list(tmp_buf)
				self.lock.release()
				if iteration_num<ITER_NOISE or np.max(np.abs(tmp_buf))>self.noise_amp*1.25:
					line+=list(tmp_buf)
				#print("BH")
				iteration_num+=1
				#print(iteration_num)
				if iteration_num<ITER_NOISE:
					median_amplitudes.append(np.median(np.abs(tmp_buf)))
				elif iteration_num==ITER_NOISE:
					self.noise_amp=np.median(median_amplitudes)
					print("VOICI LE BRUIT :",self.noise_amp)

				#utils.wait(seconds=0.001)
				#print("CH")
		finally:
			with open("debug_recv.complex","wb") as f:
				f.write(pickle.dumps(line))
			self.loop_running=False
			self.alreadyStarted=False

	def startStreaming(self):
		'''
		This method starts the streaming process.

		:return: boolean indicating if the operation was successful
		:rtype: bool

		:Example:

			>>> sdr.startStreaming()
			True

		'''
		if self.checkParameters() and not self.running:
			self.iqStream = []
			#if self.alreadyStarted:
			#	self.restart()
			self.lock.acquire()
			self.stream = self.device.setupStream(SOAPY_SDR_RX, SOAPY_SDR_CF32, [0])
			self.blockLength = self.device.getStreamMTU(self.stream)
			#self.device.setAntenna(SOAPY_SDR_RX, 0, "RX2")
			self.device.setAntenna(SOAPY_SDR_RX, 0, self.device.listAntennas(SOAPY_SDR_RX, 0)[-1])
			self.device.setGain(SOAPY_SDR_RX, 0, 55)
			self.device.activateStream(self.stream)

			self.lock.release()
			self.thread=threading.Thread(target=self._runReception)
			self.thread.start()
			#if ret == ???:
			#	self.running = True
			#	return True
			self.running=True
			return True
		return False

	def stopStreaming(self):
		'''
		This method stops the streaming process.

		:return: boolean indicating if the operation was successful
		:rtype: bool

		:Example:

			>>> sdr.stopStreaming()
			True

		'''
		#import inspect
		#print([inspect.stack()[i][3] for i in range(len(inspect.stack()))])

		if self.running:
			self.loop_continue = False
			self.thread.join(timeout=1)
			#print("DEBUG",self.stream)
			if self.stream!=None:
				self.lock.acquire()
				if self.stream!=None:
					self.device.deactivateStream(self.stream)
					ret = self.device.closeStream(self.stream)
					self.stream=None
				self.lock.release()
				self.running=False
				if ret == 0:
					self.alreadyStarted = False
					self.running = False
					return True
				else:
					return False
			else:
				return True
		return False

	def checkParameters(self):
		'''
		This method returns a boolean indicating if a mandatory parameter is missing.

		:return: boolean indicating if the source is correctly configured
		:rtype: bool

		:Example:

				>>> soapySource.checkParameters()
				[FAIL] You have to provide a frequency !
				False

		'''

		valid = True
		if self.frequency is None:
			io.fail("You have to provide a frequency !")
			valid = False
		if self.bandwidth is None:
			io.fail("You have to provide a bandwidth !")
			valid = False
		if self.gain is None:
			io.fail("You have to provide a Gain !")
			valid = False
		if self.sampleRate is None:
			io.fail("You have to provide a sample rate !")
			valid = False
		return valid

	def setBandwidth(self,bandwidth):
		SoapySDRHardware.setBandwidth(self,bandwidth)
		self.bandwidth = bandwidth

	def setFrequency(self,frequency):
		SoapySDRHardware.setFrequency(self,frequency)
		self.frequency = frequency

	def setGain(self,gain):
		SoapySDRHardware.setGain(self,gain)
		self.gain = gain

	def setSampleRate(self,sampleRate):
		SoapySDRHardware.setSampleRate(self,sampleRate)
		self.sampleRate = sampleRate



class HackRFSource(HackRFSDR,SDRSource):
	'''
	This class defines a Source for HackRF Software Defined Radio. It inherits from ``SDRSource``.
	'''

	numberOfSources = 0

	def __del__(self):
		self.close()
		HackRFSource.numberOfSources-=1
		if HackRFSource.numberOfSources == 0 and HackRFSource.initialized:
			HackRFSDR.closeAPI()

	def __init__(self,interface):
		self.alreadyStarted = False
		HackRFSDR.__init__(self,interface=interface)
		SDRSource.__init__(self,interface=interface)
		self.callback = hackrflibcallback(self._receiveCallback)

		if self.ready:
			HackRFSource.numberOfSources+=1



	def _receiveCallback(self,hackrf_transfer):
		'''
		This method implements the reception callback used by the source to receive IQ from the HackRF.
		It is not intended to be used directly, see ``startStreaming`` and ``stopStreaming`` methods to start and stop the streaming process.
		'''

		length = hackrf_transfer.contents.valid_length
		self.blockLength = length // 2
		arrayType = (c_byte*length)
		values = cast(hackrf_transfer.contents.buffer, POINTER(arrayType)).contents
		#if len(self.iqStream) < 10*length:
		self.iqStream+=[(values[i]/128.0+1j*values[i+1]/128.0) for i in range(0,len(values)-1,2)]
		return 0


	def startStreaming(self):
		'''
		This method starts the streaming process.

		:return: boolean indicating if the operation was successful
		:rtype: bool

		:Example:

			>>> hackrfSource.startStreaming()
			True

		'''
		if self.checkParameters() and not self.running:
			self.iqStream = []
			if self.alreadyStarted:
				self.restart()
			self.lock.acquire()
			ret = libhackrf.hackrf_start_rx(self.device, self.callback, None)

			self.lock.release()
			if ret == HackRfError.HACKRF_SUCCESS:
				self.running = True
				return True
		return False

	def stopStreaming(self):
		'''
		This method stops the streaming process.

		:return: boolean indicating if the operation was successful
		:rtype: bool

		:Example:

			>>> hackrfSource.stopStreaming()
			True

		'''

		if self.running:
			self.lock.acquire()
			ret = libhackrf.hackrf_stop_rx(self.device)
			self.lock.release()
			if ret == HackRfError.HACKRF_SUCCESS:
				self.alreadyStarted = True
				self.running = False
				return True
		return False

	def isStreaming(self):
		'''
		This method returns a boolean indicating if the streaming process is enabled.

		:return: boolean indicating if streaming is enabled
		:rtype: bool

		:Example:

			>>> hackrfSource.isStreaming()
			False

		'''
		self.lock.acquire()
		value = libhackrf.hackrf_is_streaming(self.device) == 1
		self.lock.release()
		return value

	def close(self):
		'''
		This method closes the HackRF Source.

		:return: boolean indicating if the operation was successful
		:rtype: bool

		:Example:

				>>> hackrfSource.close()

		'''

		if self.ready and self.device is not None:
			self.stopStreaming()
			self.lock.acquire()
			ret = libhackrf.hackrf_close(self.device)
			self.lock.release()
			return ret == HackRfError.HACKRF_SUCCESS
		return False


	def checkParameters(self):
		'''
		This method returns a boolean indicating if a mandatory parameter is missing.

		:return: boolean indicating if the source is correctly configured
		:rtype: bool

		:Example:

				>>> hackrfSource.checkParameters()
				[FAIL] You have to provide a frequency !
				False

		'''

		valid = True
		if self.frequency is None:
			io.fail("You have to provide a frequency !")
			valid = False
		if self.bandwidth is None:
			io.fail("You have to provide a bandwidth !")
			valid = False
		if self.gain is None:
			io.fail("You have to provide a VGA Gain !")
			valid = False
		if self.lnaGain is None:
			io.fail("You have to provide a LNA Gain !")
			valid = False
		if self.sampleRate is None:
			io.fail("You have to provide a sample rate !")
			valid = False
		return valid
