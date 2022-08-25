#from timestamp.timestamp import timestamp
import tools

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
		self.acl = {}
		self.vpn = {}
		self.crypto = {}
		self.nat = []
		
		while fs:
			line = fs[0].strip()
			# object and services
			if line.startswith('object'):
				if line.startswith('object network'):
					name = line[15:]
					self.nobj[name] = {
						'description':'',
						'raw':	[line],
						'flat':	[],
					}
					while fs[1].startswith(' '):
						self.nobj[name]['raw'].append(fs[1])
						if fs[1].startswith(' description'):
							self.nobj[name]['description'] = fs[1][13:]
						else:
							if fs[1].startswith(' host'):
								self.nobj[name]['flat'].append(
									f'{fs[1][6:]}/32'
								)
							elif fs[1].startswith(' subnet'):
								self.nobj[name]['flat'].append(
									tools.ip_and_mask_to_cidr(fs[1][8:])
								)
							elif fs[1].startswith(' range'):
								self.nobj[name]['flat'].extend(
									tools.ip_range_single(fs[1][7:])
								)
							else:
								pass
						del fs[1]
				elif line.startswith('object-group network'):
					#print(line)
					name = line[21:]
					self.nobj[name] = {
						'description':'',
						'raw':	[line],
						'flat':	[],
					}
					while fs[1].startswith(' '):
						self.nobj[name]['raw'].append(fs[1])
						if fs[1].startswith(' description'):
							self.nobj[name]['description'] = fs[1][13:]
						elif fs[1].startswith(' network-object object'):
							obj = fs[1][23:]
							self.nobj[name]['flat'].extend(
								self.nobj[obj]['flat']
							)
						elif fs[1].startswith(' network-object host'):
							host = fs[1][21:]
							self.nobj[name]['flat'].append(
								f'{host}/32'
							)
						elif fs[1].startswith(' group-object'):
							obj = fs[1][14:]
							self.nobj[name]['flat'].extend(
								self.nobj[obj]['flat']
							)
						else:
							self.nobj[name]['flat'].append(
								tools.ip_and_mask_to_cidr(fs[1][16:])
							)
						del fs[1]
				elif line.startswith('object service'):
					name = line[15:]
					self.sobj[name] = {
						'description':'',
						'raw':	[line],
						'flat':	[],
					}
					while fs[1].startswith(' '):
						self.sobj[name]['raw'].append(fs[1])
						if fs[1].startswith(' description'):
							self.sobj[name]['description'] = fs[1][13:]
						elif fs[1].startswith(' service tcp'):
							s = fs[1].split()
							if s[3] == 'eq':
								port = s[4]
								if not port.isnumeric():
									port = port_translate(port)
								self.sobj[name]['flat'].append(
									f'tcp/{port}'
								)
							elif s[3] == 'range':
								begin = s[4]
								if not begin.isnumeric():
									begin = port_translate(begin)
								begin = int(begin)
								end = s[5]
								if not end.isnumeric():
									end = port_translate(end)
								end = int(end)
								for x in range(begin,end+1):
									self.sobj[name]['flat'].append(
										f'tcp/{x}'
									)
							else:
								print('tcp',fs[1])
						elif fs[1].startswith(' service udp'):
							s = fs[1].split()
							if s[3] == 'eq':
								port = s[4]
								if not port.isnumeric():
									port = port_translate(port)
								self.sobj[name]['flat'].append(
									f'udp/{port}'
								)
							elif s[3] == 'range':
								begin = s[4]
								if not begin.isnumeric():
									begin = port_translate(begin)
								begin = int(begin)
								end = s[5]
								if not end.isnumeric():
									end = port_translate(end)
								end = int(end)
								for x in range(begin,end+1):
									self.sobj[name]['flat'].append(
										f'udp/{x}'
									)
							else:
								print('udp',fs[1])
						else:
							print('unknown service 218',fs[1])
						del fs[1]
				elif line.startswith('object-group service'):
					name = line[21:]
					protocol = ''
					if ' ' in name:
						name = line[21:name.index(' ')]
						protocol = line[name.index(' ')+1:]
						#print('protocol',protocol)
						## try to catch protocol
					self.sobj[name] = {
						'description':'',
						'raw':	[line],
						'protocol':	protocol,
						'flat':	[],
					}
					while fs[1].startswith(' '):
						self.sobj[name]['raw'].append(fs[1])
						if fs[1].startswith(' description'):
							self.sobj[name]['description'] = fs[1][13:]
						elif fs[1].startswith(' service-object tcp'):
							s = fs[1].split()
							if s[3] == 'eq':
								port = s[4]
								if not port.isnumeric():
									port = port_translate(port)
								self.sobj[name]['flat'].append(
									f'tcp/{port}'
								)
							elif s[3] == 'range':
								begin = s[4]
								if not begin.isnumeric():
									begin = port_translate(begin)
								begin = int(begin)
								end = s[5]
								if not end.isnumeric():
									end = port_translate(end)
								end = int(end)
								for x in range(begin,end+1):
									self.sobj[name]['flat'].append(
										f'tcp/{x}'
									)
							else:
								print('tcp',fs[1])
						elif fs[1].startswith(' service-object udp'):
							s = fs[1].split()
							if not len(s) > 2:
								print('small',s)
							elif s[3] == 'eq':
								port = s[4]
								if not port.isnumeric():
									port = port_translate(port)
								self.sobj[name]['flat'].append(
									f'udp/{port}'
								)
							elif s[3] == 'range':
								begin = s[4]
								if not begin.isnumeric():
									begin = port_translate(begin)
								begin = int(begin)
								end = s[5]
								if not end.isnumeric():
									end = port_translate(end)
								end = int(end)
								for x in range(begin,end+1):
									self.sobj[name]['flat'].append(
										f'udp/{x}'
									)
							else:
								print('udp',fs[1])
						elif fs[1].startswith(' service-object object'):
							#print(fs[1])
							obj = fs[1][23:].strip()
							if obj not in self.sobj:
								if obj.startswith('icmp-'):
									obj = 'icmp/' + obj[obj.index('-')+1:]
									self.sobj[name] = {
										'description':'',
										'raw':	[],
										'protocol':	'icmp',
										'flat':	[obj],
									}
								elif obj.startswith('tcp-'):
									obj = 'tcp/'
									port = obj[obj.index('-')+1:]
									if not port.isnumeric():
										port = port_translate(port)
									obj = obj + port
									self.sobj[name] = {
										'description':'',
										'raw':	[],
										'protocol':	'tcp',
										'flat':	[obj],
									}
								elif obj.startswith('udp-'):
									obj = 'udp/'
									port = obj[obj.index('-')+1:]
									if not port.isnumeric():
										port = port_translate(port)
									obj = obj + port
									self.sobj[name] = {
										'description':'',
										'raw':	[],
										'protocol':	'udp',
										'flat':	[obj],
									}
								else:
									print('unknown SO object',obj)
							else:
								self.sobj[name]['flat'].extend(
									self.sobj[obj]['flat']
								)
						elif fs[1].startswith(' group-object'):
							#print(fs[1])
							obj = fs[1][14:].strip()
							if obj not in self.sobj:
								if obj.startswith('icmp-'):
									obj = 'icmp/' + obj[obj.index('-')+1:]
									self.sobj[name]['flat'].append(
										obj
									)
								else:
									print('unknown GO object',obj)
							else:
								self.sobj[name]['flat'] = self.sobj[obj]['flat']
						else:
							#pass
							## this is where protocol would be
							print(fs[1])
						del fs[1]
				else:
					print('obj exception',line)
					pass
			# tunnel-group
			elif line.startswith('tunnel-group'):
				temp_split = fs[0].split(' ')
				endpoint = temp_split[1]
				if endpoint not in self.vpn:
					self.vpn[endpoint] = {}
				#
				if ' type ' in fs[0]:
					self.vpn[endpoint]['type'] = temp_split[3]
				elif '-attributes' in fs[0]:
					self.vpn[endpoint]['att'] = []
					while fs[1].startswith(' '):
						sub_temp_split = fs[1].split(' ')
						if 'pre-shared-key' in fs[1]:
							self.vpn[endpoint]['psk'] = sub_temp_split[3]
						else:
							self.vpn[endpoint]['att'].append(fs[1])
						del fs[1]
			elif line.startswith('crypto map'):
				temp_split = fs[0].split(' ')
				endpoint = temp_split[3]
				if endpoint not in self.crypto:
					self.crypto[endpoint] = {'other': []}
				#
				if 'set peer' in fs[0]:
					self.crypto[endpoint]['peer'] = temp_split[6]
				elif 'match address' in fs[0]:
					self.crypto[endpoint]['match'] = temp_split[6]
				else:
					self.crypto[endpoint]['other'].append(fs[0])
			# acl
			elif line.startswith('access-list'):
				ls = line.split(' ')
				name = ls[1]
				if name not in self.acl:
					self.acl[name] = []
				a = {
					'name': name,
					'raw': fs[0],
					'action': 'permit' if 'permit' in ls else 'deny',
					'src': [],
					'dst': [],
					'port': [],
				}
				#
				if 'extended' in ls:
					#print('[I] Extended ACL',name,ls)
					# protocol
					if ls[4] == 'ip':
						a['port'] = ['any']
						del ls[4]
					elif 'object' in ls[4]:
						a['port'] = [
							self.sobj[ls[5]]['flat']
							#ls[5]
						]
						del ls[5]
						del ls[4]
					else:
						# tcp udp esp ah
						a['port'] = [ls[4]]
						del ls[4]
					# source
					if ls[4].startswith('any'):
						a['src'] = ['any']
						del ls[4]
					elif ls[4] == 'host':
						a['src'].extend(
							f'{ls[5]}/32'
						)
					elif 'object' in ls[4]:
						a['src'].extend(
							self.nobj[ls[5]]['flat']
							#ls[5]
						)
						del ls[5]
						del ls[4]
					else:
						# network mask
						a['src'].extend(
							tools.ip_and_mask_to_cidr(
								f'{ls[4]} {ls[5]}'
							)
						)
						del ls[5]
						del ls[4]
					# destination
					if ls[4].startswith('any'):
						a['dst'] = ['any']
						del ls[4]
					elif ls[4] == 'host':
						a['dst'].extend(
							f'{ls[5]}/32'
						)
					elif 'object' in ls[4]:
						a['dst'].extend(
							self.nobj[ls[5]]['flat']
							#ls[5]
						)
						del ls[5]
						del ls[4]
					else:
						# network mask
						a['dst'].extend(
							tools.ip_and_mask_to_cidr(
								f'{ls[4]} {ls[5]}'
							)
						)
						del ls[5]
						del ls[4]
					# port
					if 'eq' in ls:
						pass
					else:
						pass
				elif 'standard' in ls:
					#print('[I] Standard ACL',name,ls)
					a['src'] = ['any']
					a['port'] = ['any']
					if 'host' in ls:
						a['dst'].extend(
							f'{ls[5]}/32'
						)
					else:
						a['dst'].extend(
							tools.ip_and_mask_to_cidr(
								f'{ls[4]} {ls[5]}'
							)
						)
						pass
				self.acl[name].append(a)
				##
				##
				##
			del fs[0]
		return
	
	def get_vpn(self, ip):
		if ip in self.vpn:
			print(f'[I] VPN tunnel exists for {ip}')
		for cm in self.crypto:
			if 'peer' in self.crypto[cm] and ip == self.crypto[cm]['peer']:
				acl_name = self.crypto[cm]['match']
				print(f'[I] VPN ACL exists for {ip} - ACL : {acl_name} - PSK : {self.vpn[ip]["psk"]}')
				for src in self.acl[acl_name][0]['src']:
					for dst in self.acl[acl_name][0]['dst']:
						print(f'{src},{dst}')
			else:
				pass
		return
	
	def get_vpn_list(self):
		for ip in self.vpn:
			for cm in self.crypto:
				if 'peer' in self.crypto[cm] and ip == self.crypto[cm]['peer']:
					print(ip, '--', self.crypto[cm]['match'])
		return
	
	def is_permit(self,src,dst,port=''):
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
					if 'any' in line_src or tools.subnet_in_supernet(src, line_src):
						for line_dst in line['dst']:
							#print('\tdst',dst,'in',line_dst,line)
							if 'any' in line_dst or tools.subnet_in_supernet(dst, line_dst):
								if line['protocol'] == 'ip' or port in line['port']: output.append(line)
		else:
			for line in self.acl:
				if line['action'] != 'permit': continue
				for line_src in line['src']:
					#print(src,'in',line_src,line)
					if 'any' in line_src or tools.subnet_in_supernet(src, line_src):
						for line_dst in line['dst']:
							#print('\tdst',dst,'in',line_dst,line)
							if 'any' in line_dst or tools.subnet_in_supernet(dst, line_dst):
								output.append(line)
		return output
#

if __name__ == '__main__':
	#filename = 'configs/CSSfdMUSashdc01-vrf14011.txt'
	#filename = 'fw.txt'
	filename = 'sg-asa555x-1.f01.justenergy..txt'
	#filename = 'sghst-asa1.f01.justenergy..txt'
	c = Config()
	c.load_config_from_file(filename)
	c.parse_config()
	
	#src = '10.152.60.7/32'
	#dst = '10.229.81.244/32'
	#port = 'tcp/1433'
	#r = c.is_permit(src,dst,port=port)
	#for result in r:
	#	print(result)
	print('[I] End')