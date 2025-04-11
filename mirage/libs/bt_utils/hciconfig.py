from fcntl import ioctl
import socket

import struct

class HCIConfig(object):
	'''
	This class allows to easily configure an HCI Interface.
	'''
	@classmethod
	def list(cls):
		sock = socket.socket(31, socket.SOCK_RAW, 1)
		try:
			arg=struct.pack('I', 16) + b"\x00"*(8*16)
			output=ioctl(sock.fileno(), 0x800448d2, arg) # GETDEVLIST
			number_of_devices = struct.unpack('H', output[:2])[0]
		except Exception:
			number_of_devices=0
		device_ids=[]
		for device_number in range(number_of_devices):
			device_id=struct.unpack('H', output[4+8*device_number:4+8*device_number+2])[0]
			device_ids.insert(0,device_id)
		return device_ids

	@staticmethod
	def down(index):
		'''
		This class method stops an HCI interface.
		Its role is equivalent to the following command : ``hciconfig hci<index> down``

		:param index: index of the HCI interface to stop 
		:type index: integer

		:Example:
	
			>>> HCIConfig.down(0)

		'''
		
		try:
			sock = socket.socket(31, socket.SOCK_RAW, 1)
			ioctl(sock.fileno(), 0x400448ca, index)
			sock.close()
		except IOError:
			return False
		return True

	@staticmethod
	def reset(index):
		'''
		This class method resets an HCI interface.
		Its role is equivalent to the following command : ``hciconfig hci<index> reset``

		:param index: index of the HCI interface to reset 
		:type index: integer

		:Example:
	
			>>> HCIConfig.reset(0)

		'''
		try:
			sock = socket.socket(31, socket.SOCK_RAW, index)
			ioctl(sock.fileno(), 0x400448cb, 0)
			sock.close()
		except IOError:
			return False
		return True

	@staticmethod
	def up(index):
		'''
		This class method starts an HCI interface.
		Its role is equivalent to the following command : ``hciconfig hci<index> up``

		:param index: index of the HCI interface to start 
		:type index: integer

		:Example:
	
			>>> HCIConfig.up(0)

		'''
		try:
			sock = socket.socket(31, socket.SOCK_RAW, index)
			ioctl(sock.fileno(), 0x400448c9, 0)
			sock.close()
		except IOError:
			return False
		return True
