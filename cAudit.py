#!/usr/bin/python

from Exscript.protocols.drivers import ios
from Exscript.protocols import Telnet
from Exscript.util.file import get_hosts_from_file
from Exscript import Account
from Exscript.util.start import start
import re
import argparse
from ciscoconfparse import CiscoConfParse

def ipsec_audit():
	parse = CiscoConfParse(filename)
	conn.execute('sho run | include set peer')             
	configured = set( re.findall( r'[0-9]+(?:\.[0-9]+){3}', conn.response ))
	conn.execute('sho crypto isa peer | include Peer:')
	live = set( re.findall( r'[0-9]+(?:\.[0-9]+){3}', conn.response ))
	print '\n'
	print 'IPSec Audit of Host:\t', h
	hostname = parse.find_objects(r"^hostname")
	for obj in hostname:
		print 'Hostname:\t\t', obj.text.split(' ',1)[1]
	conn.execute('show ver')
	ios =  re.search(r'Version[ \t]*([^\n\r]*)',conn.response)
	print 'IOS:\t\t\t', ios.group()	
	print '-----------------------------------------------------------------'
	print '\n'	
	print 'VPN Connections'
	print '---------------'	
	if args.v:
		print '\n'
		for i in configured:
			if i in live:
				print 'Endpoint: ', i , ' has a live VPN peer connection'
			else: 
				print 'Endpoint: ', i , ' is configured but not live'
		print '\n'
	print 'Total Configured VPN connections: ','\t\t\t', len(configured)
	print 'Total Live VPN Connections: ', '\t\t\t\t', len(live)
	conn.execute('sho run | include crypto isakmp key') 	
	print 'Total Number of ISAKMP Crypto keys: ','\t\t\t', len (conn.response.splitlines())-1		
	print '\n'	
	tunnels = parse.find_objects(r"interface Tunnel")
	count = 0
	ipip = 0
	gre = 0
	for obj in tunnels:
		count +=1
		if obj.re_search_children(r"tunnel mode ipip"):
			ipip +=1
			if args.v:
				print 'Tunnel', obj.text.split('nel',1)[1], "operating in IPIP mode"
		if obj.re_search_children(r"tunnel mode gre"):
			gre +=1	
			if args.v:
				print 'Tunnel', obj.text.split('nel',1)[1], "operating in GRE mode"
			print '\n'
	print 'Total Number of Tunnels Interfaces: \t\t\t', count
	print 'Total Number of Tunnels Interfaces in IPIP Mode: \t', ipip
	print 'Total Number of Tunnels Interfaces in GRE Mode: \t', gre
	print '\n'


	print 'ISAKMP Attributes'
	print '-----------------'
	dict = {'Priority':'', 'Auth':'', 'DH':'', 'Encryption':'', 'Hash':'', 'Mode':'', 'Life':''}

	isakmp_policy = parse.find_objects(r"^crypto isakmp policy")	
	print 'Priority\tAuth\t\tDH Group\tEncryption\tHash\tMode\tLifetime'
	for obj in isakmp_policy:
		dict['Priority'] = obj.text.split(' ',3)[3]
		# Encryption	
		if obj.re_search_children(r"encr DES"):
			dict['Encryption'] = 'DES'
		if obj.re_search_children(r"encr 3des"):
			dict['Encryption'] = '3DES'
		if obj.re_search_children(r"aes 256"):
			dict['Encryption'] = 'AES256'
		if obj.re_search_children(r"encr aes 192"):
			dict['Encryption'] = 'AES192'
		if obj.re_search_children(r"encr aes 256"):
			dict['Encryption'] = 'AES256'
		
		# HASH	
		if obj.re_search_children(r"hash md5"):
			dict['Hash'] = 'MD5'
		if obj.re_search_children(r"hash sha1"):
			dict['Hash'] = 'SHA1'
		if obj.re_search_children(r"hash sha256"):
			dict['Hash'] = 'SHA256'
		if not obj.re_search_children(r"hash"):	
			dict['Hash'] = 'SHA1'
	
		# DH Group
		if obj.re_search_children(r"group 1"):
			dict['DH'] = '1'
		if obj.re_search_children(r"group 2"):
			dict['DH'] = '2'
		if obj.re_search_children(r"group 3"):
			dict['DH'] = '3'
		if obj.re_search_children(r"group 14"):
			dict['DH'] = '14'

		# Authentication Method
		if obj.re_search_children(r"authentication pre-share"):
			dict['Auth'] = 'Pre-Share'
		if obj.re_search_children(r"authentication rsa"):
			dict['Auth'] = 'RSA'
		
		# Main mode vs Aggressive Mode
		if obj in parse.find_objects(r"isakmp am-disable"):
			dict['Mode'] = 'AGGR'
		else:
			dict['Mode'] = 'Main'

		# Lifetime
		#if obj.has_child_with(r'lifetime'):
		#if obj.re_search_children(r"lifetime"):		
		#	dict['Life'] = '86400'
		#else:
		#	print 'pants section not impletemented yet'
	
		print dict['Priority'],'\t\t',dict['Auth'],'\t',dict['DH'],'\t\t',dict['Encryption'],'\t\t',dict['Hash'],'\t',dict['Mode'],'\t',dict['Life']	

	print '\n'
	transport_policy = parse.find_objects(r"^crypto ipsec transform-set")
	dict = {'Name':'', 'ESP Encryption':'', 'ESP Authentication':''}
	print 'Transform Sets'
	print '--------------'	
	print 'Name\t\tESP Encryption\tESP Authentication'	
	for obj in transport_policy:
		dict['Name'] = obj.text.split(' ',5)[3]
		dict['ESP Encryption'] =obj.text.split(' ',5)[4]
		dict['ESP Authentication'] = obj.text.split(' ',5)[5]	
		print dict['Name'],'\t',dict['ESP Encryption'],'\t',dict['ESP Authentication']
	print '\n'	


def config_audit():
	print '\n'
	print 'Config Audit of Host: ', h
	print 'Nothing implemented yet'	
	print '\n'
	
	'''
	To Add:
	* Administration Access With No Host Restrictions
	* RADIUS Servers Configured With No Key
	* No Inbound TCP Connection Keep-Alives
	* No Syslog Logging Configured
	* SNMP Version (< 3 = cleartext)
	* ACL Does Not End with Deny All And Log
	* EIGRP Authentication
	* AAA settings
	'''


parser = argparse.ArgumentParser()

parser.add_argument('-u', action='store', dest='username', required=True, help='Username to log into Router')		
parser.add_argument('-p', action='store', dest='password', required=True, help='Password to log into Router')
parser.add_argument('-f', action='store', dest='filename', required=True, help='File with list of Router IP Addresses')
parser.add_argument('-v', action='store_true', default=False, help='Enable verbose Output')
parser.add_argument('-a', action='store', dest='audit', required=True, default='ipsec', help='Audit type supposed so far: "ipsec","config" or "all"')
parser.add_argument('-t', action='store', dest='conn_type', required=False, default='telnet', help='Connection method - Telnet or SSH, default is telnet')
parser.add_argument('-o', action='store', dest='output', required=False, help='File to log output to')

args = parser.parse_args()
account = Account(args.username,args.password)
if args.conn_type.lower() == 'telnet':
	conn = Telnet()
else: 
	conn = SSH2()
conn.set_driver('ios')

#if args.output:
# 	outfile = open(args.output,'w')

hosts = open(args.filename).read().splitlines()
for h in hosts:
	conn.connect(str(h))
	conn.login(account)
# 	if Error print 'Error - username and/or password wrong'
	conn.execute('terminal length 0')
	conn.execute('show run')
	conf = conn.response
	# save config to file
	filename = h+'.conf'
	conf_file = open(filename,"w")
	conf_file.write(conf)
	conf_file.close()
	if args.audit == 'ipsec':
		ipsec_audit()
	elif args.audit == 'config':
		config_audit()
#	elif args.audit == 'all':
#		ipsec_audit()
#		config_audit()
	conn.send('exit\r')
	conn.close() 
# close args.filename
# if args.output:
# 	close output