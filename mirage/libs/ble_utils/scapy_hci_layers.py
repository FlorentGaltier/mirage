from scapy.layers.bluetooth import *;from scapy.layers.bluetooth4LE import *
from scapy.fields import *
from scapy.packet import Packet

from packaging.version import Version
from scapy import __version__ as _SCAPY_VERSION
SCAPY_VERSION=Version(_SCAPY_VERSION)

VERSION_2_5_0=Version("2.5.0")
VERSION_2_6_0=Version("2.6.0")
VERSION_2_7_0=Version("2.7.0")

'''
This module contains some scapy definitions for communicating with an HCI device.
'''
#split_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Advertising_Data)
#split_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Scan_Response_Data)

class HCI_Cmd_LE_Rand(Packet):
	name = "HCI Command LE Rand"
	fields_desc = []

class HCI_Cmd_LE_Set_Host_Channel_Classification(Packet):
	name = "HCI Command LE Set Host Channel Classification"
	fields_desc = [
		BTLEChanMapField("chM" ,None)
	]
	
class HCI_LE_Meta_Enhanced_Connection_Complete(Packet):
	name = "Enhanced Connection Complete"
	fields_desc = [ByteEnumField("status", 0, {0: "success"}),
				   LEShortField("handle", 0),
				   ByteEnumField("role", 0, {0: "master"}),
				   ByteEnumField("patype", 0, {0: "public", 1: "random"}),
				   LEMACField("paddr", None),
				   LEMACField("localresolvprivaddr", None),
				   LEMACField("peerresolvprivaddr", None),
				   LEShortField("interval", 54),
				   LEShortField("latency", 0),
				   LEShortField("supervision", 42),
				   XByteField("clock_latency", 5), ]

	def answers(self, other):
		if HCI_Cmd_LE_Create_Connection not in other:
			return False

		return (other[HCI_Cmd_LE_Create_Connection].patype == self.patype and
				other[HCI_Cmd_LE_Create_Connection].paddr == self.paddr)

if SCAPY_VERSION>=VERSION_2_5_0 and SCAPY_VERSION<VERSION_2_6_0:
	print(f"WARNING: the current version of Scapy is 2.6.0 (yours is {SCAPY_VERSION})")
	print("The packet types New_HCI_Cmd_LE_Set_Advertising_Data and  New_HCI_Cmd_LE_Set_Scan_Response_Data will be replaced by the standard Scapy version starting from 2.6.0")
	class New_HCI_Cmd_LE_Set_Advertising_Data(Packet):
		name = "LE Set Advertising Data"
		fields_desc = [FieldLenField("len", None, length_of="data", fmt="B"),
					   PadField(
						   PacketListField("data", [], EIR_Hdr,
										   length_from=lambda pkt:pkt.len),
				align=31, padwith=b"\0"), ]

	class New_HCI_Cmd_LE_Set_Scan_Response_Data(Packet):
		name = "LE Set Scan Response Data"
		fields_desc = [FieldLenField("len", None, length_of="data", fmt="B"),
					   StrLenField("data", "", length_from=lambda pkt:pkt.len), ]
	bind_layers(HCI_Command_Hdr, New_HCI_Cmd_LE_Set_Advertising_Data, opcode=0x2008)
	bind_layers(HCI_Command_Hdr, New_HCI_Cmd_LE_Set_Scan_Response_Data, opcode=0x2009)
elif SCAPY_VERSION>=VERSION_2_6_0 and SCAPY_VERSION<VERSION_2_7_0:
	#New_HCI_Cmd_LE_Set_Advertising_Data=HCI_Cmd_LE_Set_Advertising_Data
	#New_HCI_Cmd_LE_Set_Scan_Response_Data=HCI_Cmd_LE_Set_Scan_Response_Data
    pass
else:
	raise Exception(f"Version {SCAPY_VERSION} of Scapy is not supported")


class SM_Security_Request(Packet):
	name = "Security Request"
	fields_desc = [BitField("authentication", 0, 8)]

class New_ATT_Handle_Value_Notification(Packet):
	name = "Handle Value Notification"
	fields_desc = [ XLEShortField("gatt_handle", 0),
					StrField("value", ""), ]


class New_ATT_Handle_Value_Indication(Packet):
	name = "Handle Value Indication"
	fields_desc = [
		XLEShortField("gatt_handle", 0),
		StrField("value", ""),
]



class New_ATT_Read_Blob_Request(Packet):
	name = "Read Blob Request"
	fields_desc = [
		XLEShortField("gatt_handle", 0),
		LEShortField("offset", 0)
	]


class New_ATT_Read_Blob_Response(Packet):
	name = "Read Blob Response"
	fields_desc = [
		StrField("value", "")
	]

class ATT_Handle_Value_Confirmation(Packet):
	name = "Handle Value Confirmation"
	fields_desc = []

bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Rand, opcode=0x2018)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Host_Channel_Classification, opcode=0x2014)
bind_layers(HCI_Event_LE_Meta, HCI_LE_Meta_Enhanced_Connection_Complete, event = 0xa)
bind_layers(SM_Hdr, SM_Security_Request, sm_command=0xb)


'''
split_layers(ATT_Hdr,ATT_Handle_Value_Notification)
bind_layers( ATT_Hdr,New_ATT_Handle_Value_Notification, opcode=0x1b)

if hasattr(scapy.all,"ATT_Handle_Value_Indication"):
	split_layers(ATT_Hdr,ATT_Handle_Value_Indication)
bind_layers( ATT_Hdr,New_ATT_Handle_Value_Indication, opcode=0x1d)

if hasattr(scapy.all,"ATT_ReadBlobReq"):
	split_layers(ATT_Hdr,ATT_ReadBlobReq)
if hasattr(scapy.all,"ATT_ReadBlobResp"):
	split_layers(ATT_Hdr,ATT_ReadBlobResp)

if hasattr(scapy.all,"ATT_Read_Blob_Request"):
	split_layers(ATT_Hdr,ATT_Read_Blob_Request)
if hasattr(scapy.all,"ATT_Read_Blob_Response"):
	split_layers(ATT_Hdr,ATT_Read_Blob_Response)

bind_layers(ATT_Hdr, New_ATT_Read_Blob_Request, opcode=0xc)
bind_layers(ATT_Hdr, New_ATT_Read_Blob_Response, opcode=0xd)
'''
bind_layers(ATT_Hdr, ATT_Handle_Value_Confirmation, opcode=0x1e)
