#from scapy.all import *
from scapy.packet import Packet
from scapy.fields import ByteField
from scapy.layers.dot15d4 import *
from scapy.layers.zigbee import *

'''
This module contains some scapy definitions for XBee packets.
'''


class Xbee_Hdr(Packet):
    description = "XBee payload"
    fields_desc = [
        ByteField("counter", None),
        ByteField("unknown", None)
]
