from application.frameworks import class_tools

def port_translate(port):
	# http://www.cisco.com/c/en/us/td/docs/security/asa/asa96/configuration/general/asa-96-general-config/ref-ports.html#ID-2120-000002b8
	d = {
		'aol':	'5190',
		'bgp':	'179',
		'biff':	'512',
		'bootpc':	'68',
		'bootps':	'67',
		'chargen':	'19',
		'cifs':	'3020',
		'citrix-ica':	'1494',
		'cmd':	'514',
		'ctiqbe':	'2748',
		'daytime':	'13',
		'discard':	'9',
		'dnsix':	'195',
		'domain':	'53',
		'echo':	'7',
		'exec':	'512',
		'finger':	'79',
		'ftp':	'21',
		'ftp-data':	'20',
		'gopher':	'70',
		'h323':	'1720',
		'hostname':	'101',
		'http':	'80',
		'https':	'443',
		'ident':	'113',
		'imap4':	'143',
		'irc':	'194',
		'isakmp':	'500',
		'kerberos':	'750',
		'klogin':	'543',
		'kshell':	'544',
		'ldap':	'389',
		'ldaps':	'636',
		'login':	'513',
		'lotusnotes':	'1352',
		'lpd':	'515',
		'mobile-ip':	'434',
		'nameserver':	'42',
		'netbios-dgm':	'138',
		'netbios-ns':	'137',
		'netbios-ssn':	'139',
		'nfs':	'2049',
		'nntp':	'119',
		'ntp':	'123',
		'pcanywhere-data':	'5631',
		'pcanywhere-status':	'5632',
		'pim-auto-rp':	'496',
		'pop2':	'109',
		'pop3':	'110',
		'pptp':	'1723',
		'radius':	'1645',
		'radius-acct':	'1646',
		'rip':	'520',
		'rsh':	'514',
		'rtsp':	'554',
		'secureid-udp':	'5510',
		'sip':	'5060',
		'smtp':	'25',
		'snmp':	'161',
		'snmptrap':	'162',
		'sqlnet':	'1521',
		'ssh':	'22',
		'sunrpc':	'111',
		'syslog':	'514',
		'tacacs':	'49',
		'talk':	'517',
		'telnet':	'23',
		'tftp':	'69',
		'time':	'37',
		'uucp':	'540',
		'vxlan':	'4789',
		'who':	'513',
		'whois':	'43',
		'www':	'80',
		'xdmcp':	'177',
	}
	if port in d:
		return d[port]
	else:
		return port

class Config(object):
	def __init__(self):
		self.config = ''
		return
	
	def load_config_from_file(self, filename):
		with open(filename,'r') as f:
			self.config = f.read()
		return
	
	def parse_config(self):
		if not self.config:
			print('[E] No config to parse')
			return
		sc = '\r\n' if '\r\n' in self.config else '\n'
		fs = self.config.split(sc)
		
		self.nobj = {}
		self.sobj = {}
		self.acl = []
		
		while fs:
			temp = []
			if fs[0].startswith('object'):
				temp.append(fs[0])
				while fs[1].startswith(' '):
					temp.append(fs[1])
					del fs[1]
				self.parse_object(temp)
			elif fs[0].startswith('access-list'):
				self.parse_acl(fs[0])
			else:
				pass
			del fs[0]
		#
		return
	
	def parse_object(self, object):
		# Network
		if (
			object[0].startswith('object network') or
			object[0].startswith('object-group network')
			):
			osplit = object[0].split()
			name = osplit[2]
			self.nobj[name] = {
				'description':	'',
				'raw':	[object[0]],
				'flat':	[],
			}
			## write object name
			del object[0]
			while object:
				if object[0].startswith(' description'):
					self.nobj[name]['raw'].append(object[0])
					self.nobj[name]['description'] = object[0]
				else:
					self.nobj[name]['raw'].append(object[0])
					self.nobj[name]['flat'].extend(
						self.parse_object_child(object[0], 'network')
					)
				del object[0]
		# Service
		elif (
			object[0].startswith('object service') or
			object[0].startswith('object-group service')
			):
			osplit = object[0].split()
			if len(osplit) > 3: print(osplit)
			name = osplit[2]
			#print('service',name)
			self.sobj[name] = {
				'description':	'',
				'raw':	[object[0]],
				'flat':	[],
			}
			## write object name
			del object[0]
			while object:
				if object[0].startswith(' description'):
					self.sobj[name]['raw'].append(object[0])
					self.sobj[name]['description'] = object[0]
				else:
					self.sobj[name]['raw'].append(object[0])
					self.sobj[name]['flat'].extend(
						self.parse_object_child(object[0], 'service')
					)
				del object[0]
		else:
			print('[E] unknown object type: ',object[0])
			pass
		return
	
	def parse_object_child(self, child, object_type):
		#print(child,object_type)
		result = []
		if object_type == 'network':
			if child.startswith(' host'):
				result = [
					f'{child[6:]}/32'
				]
			elif child.startswith(' subnet'):
				result = [
					class_tools.ip_and_mask_to_cidr(
						child[8:]
					)
				]
			elif child.startswith(' range'):
				result = class_tools.ip_range_single(
					child[7:]
				)
			elif child.startswith(' network-object object'):
				obj_name = child[23:]
				result = self.nobj[obj_name]['flat']
				pass
			elif child.startswith(' network-object host'):
				result = [
					f'{child[21:]}/32'
				]
			elif child.startswith(' network-object '):
				if child[16].isnumeric():
					result = [
						class_tools.ip_and_mask_to_cidr(
							child[16:]
						)
					]
					#print(result)
				else:
					#print(child)
					pass
				pass
			elif child.startswith(' group-object'):
				obj_name = child[14:]
				result = self.nobj[obj_name]['flat']
			else:
				print('[E] unknown network: ',object[0])
		elif object_type == 'service':
			if child.startswith(' service tcp'):
				cs = child.split()
				if cs[3] == 'eq':
					port = cs[4]
					if not port.isnumeric():
						port = port_translate(port)
					result = [
						f'tcp/{port}'
					]
				elif cs[3] == 'range':
					begin = cs[4]
					if not begin.isnumeric():
						begin = port_translate(begin)
					begin = int(begin)
					#
					end = cs[5]
					if not end.isnumeric():
						end = port_translate(end)
					end = int(end)
					result = [
						f'tcp/{x}'
						for x in range(begin, end+1)
					]
				else:
					pass
			elif child.startswith(' service udp'):
				cs = child.split()
				if cs[3] == 'eq':
					port = cs[4]
					if not port.isnumeric():
						port = port_translate(port)
					result = [
						f'udp/{port}'
					]
				elif cs[3] == 'range':
					begin = cs[4]
					if not begin.isnumeric():
						begin = port_translate(begin)
					begin = int(begin)
					#
					end = cs[5]
					if not end.isnumeric():
						end = port_translate(end)
					end = int(end)
					result = [
						f'tcp/{x}'
						for x in range(begin, end+1)
					]
				else:
					pass
			elif child.startswith(' service-object tcp'):
				cs = child.split()
				if cs[3] == 'eq':
					port = cs[4]
					if not port.isnumeric():
						port = port_translate(port)
					result = [
						f'tcp/{port}'
					]
				elif cs[3] == 'range':
					begin = cs[4]
					if not begin.isnumeric():
						begin = port_translate(begin)
					begin = int(begin)
					#
					end = cs[5]
					if not end.isnumeric():
						end = port_translate(end)
					end = int(end)
					result = [
						f'tcp/{x}'
						for x in range(begin, end+1)
					]
				else:
					pass
			elif child.startswith(' service-object udp'):
				cs = child.split()
				if cs[3] == 'eq':
					port = cs[4]
					if not port.isnumeric():
						port = port_translate(port)
					result = [
						f'udp/{port}'
					]
				elif cs[3] == 'range':
					begin = cs[4]
					if not begin.isnumeric():
						begin = port_translate(begin)
					begin = int(begin)
					#
					end = cs[5]
					if not end.isnumeric():
						end = port_translate(end)
					end = int(end)
					result = [
						f'udp/{x}'
						for x in range(begin, end+1)
					]
				else:
					pass
			elif child.startswith(' service-object icmp'):
				cs = child.split()
				port = cs[2]
				if not port.isnumeric():
					port = port_translate(port)
				result = [
					f'icmp/{port}'
				]
			elif child.startswith(' service-object object'):
				cs = child.split()
				if cs[2] not in self.sobj:
					if cs[2].startswith('icmp-'):
						result = [
							f'icmp/{cs[2][5:]}'
						]
					elif cs[2].startswith('tcp-'):
						result = [
							f'tcp/{cs[2][4:]}'
						]
					elif cs[2].startswith('udp-'):
						result = [
							f'udp/{cs[2][4:]}'
						]
				else:
					result = self.sobj[cs[2]]['flat']
			elif child.startswith(' port-object'):
				cs = child.split()
				if cs[1] == 'eq':
					port = cs[2]
					if not port.isnumeric():
						port = port_translate(port)
					result = [
						f'tcp/{port}'
					]
				else:
					pass
			elif child.startswith(' group-object'):
				cs = child.split()
				if cs[1] not in self.sobj:
					if cs[1].startswith('icmp-'):
						result = [
							f'icmp/{cs[2][6:]}'
						]
					elif cs[1].startswith('tcp-'):
						result = [
							f'tcp/{cs[2][5:]}'
						]
					elif cs[1].startswith('udp-'):
						result = [
							f'udp/{cs[2][5:]}'
						]
					else:
						print('[E] Unknown GO :',cs[1])
				else:
					result = self.sobj[cs[1]]['flat']
			else:
				print('[E] unknown service: ',object[0])
		else:
			pass
		return result
	
	def parse_acl(self, line):
		line = line.strip()
		ls = line.split()
		keys = [
			'raw',
			'name',
			'extended',
			# 'remark',
		]
		aaa = dict.fromkeys(keys)
		aaa['raw'] = line
		iteration = 0
		while ls:
			if iteration == 0:
				# acces-list
				pass
			elif iteration == 1:
				# name
				aaa['name'] = ls[0]
			elif iteration == 2:
				# standard / extended / remark
				if ls[0] == 'remark':
					break
				elif ls[0] == 'standard':
					aaa['extended'] = False
				elif ls[0] == 'extended':
					aaa['extended'] = True
				else:
					pass
			elif iteration == 3:
				# action
				if aaa['extended']:
					aaa['action'] = ls[0]
				elif not aaa['extended']:
					pass
				else:
					pass
			elif iteration == 4:
				# protocol / protocol object
				if aaa['extended']:
					if ls[0].startswith('object'):
						del ls[0]
						aaa['protocol'] = 'object'
						if ls[0] not in self.sobj:
							if ls[0].startswith('icmp-'):
								aaa['port'] = [
									f'icmp/{ls[0][5:]}'
								]
							elif ls[0].startswith('tcp-'):
								aaa['port'] = [
									f'tcp/{ls[0][4:]}'
								]
							elif ls[0].startswith('udp-'):
								aaa['port'] = [
									f'udp/{ls[0][4:]}'
								]
							else:
								pass
						else:
							aaa['port'] = self.sobj[ls[0]]['flat']
					elif ls[0] == 'ip':
						aaa['protocol'] = ls[0]
					elif ls[0] == 'tcp':
						aaa['protocol'] = ls[0]
					elif ls[0] == 'udp':
						aaa['protocol'] = ls[0]
					elif ls[0] == 'icmp':
						aaa['protocol'] = ls[0]
					else:
						pass
				elif not aaa['extended']:
					pass
				else:
					pass
			elif iteration == 5:
				# source
				if aaa['extended']:
					if ls[0].startswith('object'):
						del ls[0]
						aaa['src'] = self.nobj[ls[0]]['flat']
					elif ls[0] == 'host':
						del ls[0]
						aaa['src'] = [
							f'{ls[0]}/32'
						]
					elif ls[0].startswith('any'):
						aaa['src'] = [
							'any'
						]
					elif ls[0][0].isnumeric():
						ip_and_mask = f'{ls[0]} {ls[1]}'
						del ls[0]
						aaa['src'] = [
							class_tools.ip_and_mask_to_cidr(ip_and_mask)
						]
					else:
						pass
				elif not aaa['extended']:
					pass
				else:
					pass
			elif iteration == 6:
				# destination
				if aaa['extended']:
					if ls[0].startswith('object'):
						del ls[0]
						aaa['dst'] = self.nobj[ls[0]]['flat']
					elif ls[0] == 'host':
						del ls[0]
						aaa['dst'] = [
							f'{ls[0]}/32'
						]
					elif ls[0].startswith('any'):
						aaa['dst'] = [
							'any'
						]
					elif ls[0][0].isnumeric():
						ip_and_mask = f'{ls[0]} {ls[1]}'
						del ls[0]
						aaa['dst'] = [
							class_tools.ip_and_mask_to_cidr(ip_and_mask)
						]
					else:
						pass
				elif not aaa['extended']:
					pass
				else:
					pass
			elif iteration == 7:
				# port
				if aaa['extended']:
					if ls[0].startswith('object'):
						del ls[0]
						aaa['port'] = self.sobj[ls[0]]['flat']
					elif ls[0] == 'eq':
						del ls[0]
						if not ls[0].isnumeric():
							aaa['port'] = [
								f'{aaa["protocol"]}/{port_translate(ls[0])}'
							]
						else:
							aaa['port'] = [
								f'{aaa["protocol"]}/{ls[0]}'
							]
					elif ls[0] == 'range':
						del ls[0]
						begin = ls[0]
						if not begin.isnumeric():
							begin = port_translate(begin)
						begin = int(begin)
						#
						del ls[0]
						end = ls[0]
						if not end.isnumeric():
							end = port_translate(end)
						end = int(end)
						aaa['port'] = [
							f'{aaa["protocol"]}/{x}'
							for x in range(begin, end+1)
						]
					elif ls[0] == 'log':
						break
					else:
						pass
				elif not aaa['extended']:
					pass
				else:
					pass
				self.acl.append(aaa)
			elif iteration == 8:
				# log
				if aaa['extended']:
					if ls[0] == 'log':
						break
					else:
						pass
				elif not aaa['extended']:
					pass
				else:
					pass
			elif iteration >= 9:
				# idk
				if aaa['extended']:
					pass
				elif not aaa['extended']:
					pass
				else:
					pass
			else:
				pass
			iteration += 1
			del ls[0]
		#self.acl.append(aaa)
		return

	def is_permit(self, src, dst, port=''):
		output = []
		# fix host entries
		if '/' not in src:
			src += '/32'
		if '/' not in dst:
			dst += '/32'
		if port:
			for line in self.acl:
				if line['action'] != 'permit': continue
				for line_src in line['src']:
					#print(src,'in',line_src,line)
					if 'any' in line_src or class_tools.subnet_in_supernet(src, line_src):
						for line_dst in line['dst']:
							#print('\tdst',dst,'in',line_dst,line)
							if 'any' in line_dst or class_tools.subnet_in_supernet(dst, line_dst):
								if line['protocol'] == 'ip' or port in line['port']: output.append(line)
		else:
			for line in self.acl:
				if line['action'] != 'permit': continue
				for line_src in line['src']:
					#print(src,'in',line_src,line)
					if 'any' in line_src or class_tools.subnet_in_supernet(src, line_src):
						for line_dst in line['dst']:
							#print('\tdst',dst,'in',line_dst,line)
							if 'any' in line_dst or class_tools.subnet_in_supernet(dst, line_dst):
								output.append(line)
		return output

if __name__ == '__main__':
	filename = 'CSSfdMUSashdc01-vrf14011.txt'
	#filename = 'acl.txt'
	c = Config()
	c.load_config_from_file(filename)
	c.parse_config()
	
	src = '10.152.60.7/32'
	dst = '10.229.81.244/32'
	port = 'tcp/1433'
	# 610ms
	r = c.is_permit(src,dst,port=port)
	for result in r:
		print(result)
	print('[I] End')