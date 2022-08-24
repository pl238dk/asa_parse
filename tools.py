import struct
import socket

#
## ip to x

def ip_to_bin(ip):
	octets = ip.split('.')
	octets_integer = [int(x) for x in octets]
	#octets_bin = [bin(x)[2:] for x in octets_integer]
	output = ''.join([bin(x)[2:].zfill(8) for x in octets_integer])
	'''
	output = ''
	for octet in octets_bin:
		if len(octet) < 8:
			left = 8 - len(octet)
			output += '0' * left
		output += octet
	#'''
	return output

def ip_to_int(ip):
	ip_bytes = socket.inet_aton(ip)
	output = struct.unpack('!I', ip_bytes)[0]
	'''
	octets = ip.split('.')
	octets_integer = [int(x) for x in octets]
	o1 = octets_integer[0] * (256**3)
	o2 = octets_integer[1] * (256**2)
	o3 = octets_integer[2] * (256**1)
	o4 = octets_integer[3] * (256**0)
	output = o1 + o2 + o3 + o4
	#'''
	return output

#
## bin to x

def bin_to_ip(binary):
	o1 = binary[0:8]
	o2 = binary[8:16]
	o3 = binary[16:24]
	o4 = binary[24:32]
	octets_bin = [o1,o2,o3,o4]
	output = '.'.join([str(int(x,2)) for x in octets_bin])
	return output

def bin_to_int(binary):
	return int(binary, 2)

#
## int to x

def int_to_bin(integer):
	output = bin(integer)[2:].zfill(32)
	'''
	output = ''
	if len(binary) < 32:
		left = 32 - len(binary)
		output += '0' * left
	output += binary
	#'''
	return output

def int_to_ip(integer):
	ip_bytes = struct.pack('!I',integer)
	output = socket.inet_ntoa(ip_bytes)
	'''
	binary = int_to_bin(integer)
	output = bin_to_ip(binary)
	#'''
	return output

#
## cidr to x

def cidr_to_bin(cidr):
	mask = (0xffffffff >> (32 - int(cidr))) << (32 - int(cidr))
	#output = int_to_ip(mask)
	output = bin(mask)[2:].zfill(32)
	'''
	cidr_int = int(cidr)
	output = '1' * cidr_int + '0' * (32-cidr_int)
	#'''
	return output

def cidr_to_ip(cidr):
	mask = (0xffffffff >> (32 - int(cidr))) << (32 - int(cidr))
	output = str(
		str( (0xff000000 & mask) >> 24) + '.' +
		str( (0x00ff0000 & mask) >> 16) + '.' +
		str( (0x0000ff00 & mask) >> 8) + '.' +
		str( (0x000000ff & mask) >> 0) + '.'
	)
	'''
	binary = cidr_to_bin(cidr)
	output = binary_to_ip(binary)
	#'''
	return output

#
## other

def ip_range(start, end):
	'''
	returns a list of all IPs from start to end, inclusive
	'''
	s = ip_to_int(start)
	f = ip_to_int(end)
	output = []
	for middle in range(s,f+1):
		output.append(f'{int_to_ip(middle)}/32')
		#binary = int_to_bin(middle)
		#output.append(f'{bin_to_ip(binary)}/32')
	return output

def ip_range_single(ip_range):
	start,end = ip_range.split()
	s = ip_to_int(start)
	f = ip_to_int(end)
	output = []
	for middle in range(s,f+1):
		output.append(f'{int_to_ip(middle)}/32')
		#output.append(f'{bin_to_ip(binary)}/32')
	return output

def subnet_msb(subnet):
	ip, cidr = subnet.split('/')
	#ip = ip_to_int(ip)
	cidr = int(cidr)
	#mask = (0xffffffff >> (32 - int(cidr))) << (32 - int(cidr))
	#network = ip & mask
	#'''
	binary = ip_to_bin(ip)
	output = binary[:cidr]
	#'''
	return output

def msb_fill(msb, fill):
	right = 32 - len(msb)
	output = msb + fill * right
	return output

def subnet_to_list(subnet):
	ip, cidr = subnet.split('/')
	cidr = int(cidr)
	cidr_mask = bin_to_ip(cidr_to_bin(cidr))
	network_bin = int_to_bin(int(ip_to_bin(cidr_mask),2) & int(ip_to_bin(ip),2))
	network = bin_to_ip(network_bin)
	broadcast_prepare = '0' * cidr + '1' * (32 - cidr)
	broadcast_bin = int_to_bin(int(ip_to_bin(network),2) ^ int(broadcast_prepare,2))
	broadcast = bin_to_ip(broadcast_bin)
	output = ip_range(network, broadcast)
	return output

def ip_and_mask_to_cidr(subnet):
	ip, mask = subnet.split()
	mask_bin = ip_to_bin(mask)
	mask_ones = mask_bin.count('1')
	output = f'{ip}/{mask_ones}'
	return output

def subnet_in_supernet(sub, sup):
	# subnet
	sub_ip, sub_cidr = sub.split('/')
	sub_cidr_int = int(sub_cidr)
	sub_ip_b, sub_cidr_b = ip_to_bin(sub_ip), cidr_to_bin(sub_cidr_int)
	sub_net = int(sub_ip_b,2) & int(sub_cidr_b,2)
	sub_net_b = int_to_bin(sub_net)
	# supernet
	sup_ip, sup_cidr = sup.split('/')
	sup_cidr_int = int(sup_cidr)
	sup_ip_b, sup_cidr_b = ip_to_bin(sup_ip), cidr_to_bin(sup_cidr_int)
	sup_net = int(sup_ip_b,2) & int(sup_cidr_b,2)
	sup_net_b = int_to_bin(sup_net)
	#
	if sub_net_b[:sup_cidr_int] == sup_net_b[:sup_cidr_int]:
		return True
	return False