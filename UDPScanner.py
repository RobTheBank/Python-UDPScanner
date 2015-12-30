import threading
import time
from netaddr import IPNetwork, IPAddress 
import getopt
import socket
import os
import sys
import struct
from ctypes import *

host = ""

subnet = ""

magic_message = "PYTHONRULES!"


def udp_sender(subnet, magic_message):
	time.sleep(5)
	sender = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

	for ip in IPNetwork(subnet):
		try:
			sender.sendto(magic_message,("%s" % ip,65212))
		except:
			pass

class IP(Structure):
	_fields_ = [
		("ihl", 			c_uint8, 4),
		("version", 		c_uint8, 4),
		("tos",				c_uint8),
		("len",				c_uint16),
		("id",				c_uint16),
		("offset",			c_uint16),
		("ttl",				c_uint8),
		("protocol_num",	c_uint8),
		("sum",				c_uint16),
		("src",				c_uint32),
		("dst",				c_uint32)
	]

	def __new__(self, socket_buffer=None):
		return self.from_buffer_copy(socket_buffer)

	def __init__(self, socket_buffer=None):
		self.protocol_map = {1:"ICMP", 6:"TCP",	17:"UDP"}

		self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
		self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

		try:
			self.protocol = self.protocol_map[self.protocol_num]
		except:
			self.protocol = str(self.protocol_num)

class ICMP(Structure):
	
	_fields_ = [
		("type", 			c_uint8),
		("code", 			c_uint8),
		("checksum", 		c_uint16),
		("unused",			c_uint16),
		("next_hop_mtu",	c_uint16)
	]
	def __new__(self, socket_buffer):
		return self.from_buffer_copy(socket_buffer)

	def __init__(self, socket_buffer):
		pass
	
def usage():
	print "UDP Scanner in subnet"
	print "How to use?"
	print "-h --host   : Your computer IP."
	print "-t --target : The target you want to scan in subnet. Example:192.168.1.0/24"
	print ""
	print "Example: sudo python UDPScanner.py -h 192.168.1.103 -t 192.168.1.0/24"
	sys.exit(0)

if not len(sys.argv[1:]):
	usage()
	sys.exit(0)

try: 
	opts,args = getopt.getopt(sys.argv[1:],"h:t:",["host","target"])

except getopt.GetoptError as err:
	print str(err)
	usage()

for o,a in opts:
	if o in ("-h","--host"):
		host = a
	elif o in ("-t","--target"):
		subnet = a
	else:
		pass

print "[*] host: %s" % host
print "[*] Scan: %s" % subnet

if os.name == "nt":
	socket_protocol = socket.IPPROTO_IP
else:
	socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((host,0))

if os.name == "nt":
	sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

t = threading.Thread(target=udp_sender, args=(subnet,magic_message))
t.start()

try:
	while True:
		raw_buffer = sniffer.recvfrom(65565)[0]

		ip_header = IP(raw_buffer[0:20])

		#print "Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)

		if ip_header.protocol == "ICMP":
			offset = ip_header.ihl * 4
			buf = raw_buffer[offset:offset + sizeof(ICMP)]

			icmp_header = ICMP(buf)

			#print "ICMP -> Type: %d Code: %d" % (icmp_header.type, icmp_header.code)
			if icmp_header.code == 3 and icmp_header.type == 3:
				if IPAddress(ip_header.src_address) in IPNetwork(subnet):
					if raw_buffer[len(raw_buffer)-len(magic_message):] == magic_message:
						print "Host Up: %s" % ip_header.src_address



except KeyboardInterrupt:
	if os.name == "nt":
		sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)





