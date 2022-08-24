#import time
import tools
from port_translate import *
#from timestamp.timestamp import timestamp

class Config(object):
	def __init__(self):
		self.config = ''
		self.object = {}
		self.acl = {}
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
		
		while fs:
			line = fs[0].strip()
			if line.startswith('object'):
				osplit = line.split()
				name = osplit[2]
				if name not in self.object:
					self.object[name] = {
						'raw': [line],
						'description': '',
						'category': osplit[0],
						'type': osplit[1],
						'protocol': '',
						'flat': [],
					}
				# service protocol exception
				if len(osplit) == 4:
					self.object[name]['protocol'] = osplit[3]
				# nested object parameters
				while fs[1].startswith(' '):
					self.object[name]['raw'].append(fs[1])
					del fs[1]
				self.parse_object(self.object[name])
			elif line.startswith('access-list'):
				self.parse_acl(line)
			elif line.startswith('crypto map'):
				pass
			elif line.startswith('tunnel-group'):
				pass
			elif line.startswith('nat ('):
				pass
			# end conditional check
			del fs[0]
		return
	
	def parse_object(self, object):
		for line in object['raw'][1:]:
			if line.startswith(' description'):
				object['description'] = line
				continue
			osplit = line.split()
			if line.startswith(' host'):
				object['flat'].append(
					f'{osplit[1]}/32'
				)
			elif line.startswith(' subnet'):
				object['flat'].append(
					tools.ip_and_mask_to_cidr(line[8:])
				)
			elif line.startswith(' nat'):
				continue
			elif line.startswith(' fqdn'):
				continue
			elif line.startswith(' range'):
				object['flat'].extend(
					tools.ip_range_single(line[7:])
				)
			elif line.startswith(' port-object'):
				port = port_translate(osplit[2])
				object['flat'].append(
					f'{object["protocol"]}/{port}'
				)
			elif line.startswith(' service-object'):
				#print(osplit)
				if osplit[1] == 'object':
					if osplit[2] not in self.object:
						self.object[osplit[2]] = {
							'raw': [line],
							'description': 'default',
							'category': 'object',
							'type': object['type'],
							'protocol': '',
							'flat': [
								f'???/{osplit[2]}'
							],
						}
					else:
						port = port_translate(osplit[2])
						object['flat'].extend(
							self.object[osplit[2]]['flat']
						)
				else:
					if osplit[1] == 'icmp':
						object['flat'].append(
							f'{osplit[1]}/{osplit[2]}'
						)
					elif osplit[3] == 'eq':
						port = port_translate(osplit[4])
						object['flat'].append(
							f'{osplit[1]}/{port}'
						)
					elif osplit[3] == 'range':
						port_begin = int(port_translate(osplit[4]))
						port_end = int(port_translate(osplit[5]))
						for x in range(port_begin,port_end+1):
							object['flat'].append(
								f'{osplit[1]}/{x}'
							)
					else:
						#print(line)
						continue
			elif line.startswith(' service'):
				#print(osplit)
				if osplit[3] == 'eq':
					port = port_translate(osplit[4])
					object['flat'].append(
						f'{osplit[1]}/{port}'
					)
				elif osplit[3] == 'range':
					port_begin = int(port_translate(osplit[4]))
					port_end = int(port_translate(osplit[5]))
					for x in range(port_begin,port_end+1):
						object['flat'].append(
							f'{osplit[1]}/{x}'
						)
				else:
					#print(line)
					continue
			elif line.startswith(' network-object'):
				if osplit[1] == 'host':
					object['flat'].append(
						f'{osplit[2]}/32'
					)
				elif osplit[1][0].isdigit():
					object['flat'].append(
						tools.ip_and_mask_to_cidr(
							f'{osplit[1]} {osplit[2]}'
						)
					)
				elif osplit[1] == 'object':
					object['flat'].extend(
						self.object[osplit[2]]['flat']
					)
				else:
					print(osplit[1])
				continue
			elif line.startswith(' group-object'):
				object['flat'].extend(
					self.object[osplit[1]]['flat']
				)
			else:
				print(line)
		return
	
	def parse_acl(self, line):
		ls = line.split(' ')
		name = ls[1]
		if name not in self.acl:
			self.acl[name] = []
		a = {
			'name': name,
			'raw': line,
			'action': '',
			'protocol': '',
			'src': [],
			'dst': [],
			'port': [],
		}
		# extended acl
		if 'extended' in ls:
			#print('[I] Extended ACL',name,ls)
			# action
			a['action'] = ls[3]
			del ls[3]
			# protocol
			if ls[3] == 'ip':
				a['port'] = ['any']
				del ls[3]
			elif 'object' in ls[3]:
				if ls[4] not in self.object:
					protocol,port = ls[4].split('-')
					port = port_translate(port)
					a['port'] = [f'{protocol}/{port}']
				else:
					a['port'] = self.object[ls[4]]['flat']
				del ls[4]
				del ls[3]
			else:
				# tcp udp esp ah
				a['protocol'] = ls[3]
				del ls[3]
			# source
			if ls[3].startswith('any'):
				a['src'] = ['any']
				del ls[3]
			elif ls[3] == 'host':
				a['src'].append(
					f'{ls[4]}/32'
				)
				del ls[4]
				del ls[3]
			elif 'object' in ls[3]:
				a['src'].extend(
					self.object[ls[4]]['flat']
					#ls[4]
				)
				del ls[4]
				del ls[3]
			else:
				# network mask
				a['src'].append(
					tools.ip_and_mask_to_cidr(
						f'{ls[3]} {ls[4]}'
					)
				)
				del ls[4]
				del ls[3]
			# destination
			if ls[3].startswith('any'):
				a['dst'] = ['any']
				del ls[3]
			elif ls[3] == 'host':
				a['dst'].append(
					f'{ls[4]}/32'
				)
				del ls[4]
				del ls[3]
			elif 'object' in ls[3]:
				a['dst'].extend(
					self.object[ls[4]]['flat']
					#ls[4]
				)
				del ls[4]
				del ls[3]
			else:
				# network mask
				a['dst'].append(
					tools.ip_and_mask_to_cidr(
						f'{ls[3]} {ls[4]}'
					)
				)
				del ls[4]
				del ls[3]
			# port
			if len(ls) > 3:
				if ls[3] == 'eq':
					port = port_translate(ls[4])
					a['port'].append(
						f'{a["protocol"]}/{port}'
					)
				elif ls[3] == 'range':
					port_begin = int(port_translate(ls[4]))
					port_end = int(port_translate(ls[5]))
					for x in range(port_begin,port_end+1):
						a['port'].append(
							f'{a["protocol"]}/{x}'
						)
				elif ls[3] in ['object','object-group']:
					a['port'].extend(
						self.object[ls[4]]['flat']
						#ls[4]
					)
					del ls[4]
					del ls[3]
			else:
				#print(ls)
				pass
		# standard acl
		elif 'standard' in ls:
			#print('[I] Standard ACL',name,ls)
			a['src'] = ['any']
			a['port'] = ['any']
			if 'host' in ls:
				a['dst'].append(
					f'{ls[5]}/32'
				)
			else:
				a['dst'].append(
					tools.ip_and_mask_to_cidr(
						f'{ls[4]} {ls[5]}'
					)
				)
				pass
		self.acl[name].append(a)
		return
	
	def _(self):
		return

	def is_permit(self, src, dst, port=''):
		output = []
		# fix host entries
		if '/' not in src:
			src += '/32'
		if '/' not in dst:
			dst += '/32'
		if port:
			for acl in self.acl:
				for line in self.acl[acl]:
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

if __name__ == '__main__':
	filename = 'fw.txt'
	c = Config()
	c.load_config_from_file(filename)
	c.parse_config()
	
	
	
	print('[I] End')