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
	conn.execute('sho run | include set peer')             
	configured = set( re.findall( r'[0-9]+(?:\.[0-9]+){3}', conn.response ))
	conn.execute('sho crypto isa peer | include Peer:')
	live = set( re.findall( r'[0-9]+(?:\.[0-9]+){3}', conn.response ))
	print '\n'
	print 'IPSec Audit of Host: ', h
	print '-----------------------------------'
	print '\n'	
	print 'VPN Connections'
	print '---------------'	
	if args.v:
		print 'Verbose Mode on' 
		for i in configured:
			if i in live:
				print 'Endpoint: ', i , ' has a live VPN peer connection'
			else: 
				print 'Endpoint: ', i , ' is configured but not live'
	
	print 'Total Configured VPN connections: ', len(configured)
	print 'Total Live VPN Connections: ', len(live)
	conn.execute('sho run | include crypto isakmp key') 
	#print conn.response	
	print 'Total Number of ISAKMP Crypto keys: ', len (conn.response.splitlines())-1	
	print '\n'
	print 'ISAKMP Attributes'
	print '----------------'
	parse = CiscoConfParse(filename)
	
	#print 'Priority\tAuth\tDH Group\tEncryption\tHash\tMode\tLife'
	#print '--------\t----\t--------\t----------\t----\t----\t----'	
	#print '10\t\tPSK\tGroup2\t\t3DES\t\tMD5\tAggr\t1440mins'	
	#print '\n'
	dict = {'Priority':'', 'Auth':'', 'DH':'', 'Encryption':'', 'Hash':'', 'Mode':'', 'Life':''}

	isakmp_policy = parse.find_objects(r"^crypto isakmp policy")
	
	for obj in isakmp_policy:
		dict['Priority'] = obj.text.split(' ',3)[3]
		# Encryption	
		if obj.re_search_children(r"encr DES"):
			#print 'ISAKMP Policy',obj.text.split(' ',3)[3], 'Has DES as encryption'
			dict['Encryption'] = 'DES'
		if obj.re_search_children(r"encr 3des"):
			#print 'ISAKMP Policy',obj.text.split(' ',3)[3], 'Has 3DES as encryption'
			dict['Encryption'] = '3DES'
		if obj.re_search_children(r"aes 256"):
			#print 'ISAKMP Policy',obj.text.split(' ',3)[3], 'Has AES 256 as encryption'
			dict['Encryption'] = 'AES256'
		if obj.re_search_children(r"encr aes 192"):
			#print 'ISAKMP Policy',obj.text.split(' ',3)[3], 'Has AES 192 as encryption'
			dict['Encryption'] = 'AES192'
		if obj.re_search_children(r"encr aes 256"):
			#print 'ISAKMP Policy',obj.text.split(' ',3)[3], 'Has AES 256 as encryption'
			dict['Encryption'] = 'AES256'
		
		# HASH	
		if obj.re_search_children(r"hash md5"):
			#print 'ISAKMP Policy',obj.text.split(' ',3)[3], 'Has MD5 Authentication'
			dict['Hash'] = 'MD5'
		if obj.re_search_children(r"hash sha1"):
			#print 'ISAKMP Policy',obj.text.split(' ',3)[3], 'Has SHA1 Authentication'
			dict['Hash'] = 'SHA1'
		if obj.re_search_children(r"hash sha256"):
			#print 'ISAKMP Policy',obj.text.split(' ',3)[3], 'Has SHA256 Authentication'
			dict['Hash'] = 'SHA256'
		if not obj.re_search_children(r"hash"):	
			print 'SHA1'
	
		# DH Group
		if obj.re_search_children(r"group 1"):
			#print 'ISAKMP Policy',obj.text.split(' ',3)[3], 'Has DG Group 1'
			dict['DH'] = '1'
		if obj.re_search_children(r"group 2"):
			#print 'ISAKMP Policy',obj.text.split(' ',3)[3], 'Has DG Group 2'
			dict['DH'] = '2'
		if obj.re_search_children(r"group 3"):
			#print 'ISAKMP Policy',obj.text.split(' ',3)[3], 'Has DG Group 3'
			dict['DH'] = '3'
		if obj.re_search_children(r"group 14"):
			#print 'ISAKMP Policy',obj.text.split(' ',3)[3], 'Has DG Group 14'
			dict['DH'] = '14'

		# Authentication Method
		if obj.re_search_children(r"authentication pre-share"):
			#print 'ISAKMP Policy',obj.text.split(' ',3)[3], 'Has Pre-Share Authentication'
			dict['Auth'] = 'Pre-Share'
		if obj.re_search_children(r"authentication rsa"):
			#print 'ISAKMP Policy',obj.text.split(' ',3)[3], 'Has RSA Authentication'
			dict['Auth'] = 'RSA'
		
		# Main mode vs Aggressive Mode
		if obj in parse.find_objects(r"isakmp am-disable"):
			#print 'Phase 1 ISAKMP negotiations uses aggressive mode'
			dict['Mode'] = 'AGGR'
		else:
			#print 'Phase 1 ISAKMP negotiations uses main mode'
			dict['Mode'] = 'Main'

		# Lifetime
	# The lifetime of the SA, 500 seconds in this case, is shown in this command. 
	# If you do not set a lifetime, it defaults to 86400 seconds, or one day. 
	# When the lifetime timer fires, the SA is renegotiated as a security measure.
	# dt3-45a(config-isakmp)#lifetime 500
		
		#if obj.has_child_with(r'lifetime'):
		#if obj.re_search_children(r"lifetime"):
		#	print 'ISAKMP Policy',obj.text.split(' ',3)[3], 'Has Pre-Share Authentication'
		#	dict['Life'] = '86400'
		#else:
		#	print 'pants section not impletemented yet'


		print 'Priority\tAuth\t\tDH Group\tEncryption\tHash\tMode\tLife'
		print '--------\t----\t\t--------\t----------\t----\t----\t----'	
		print dict['Priority'],'\t\t',dict['Auth'],'\t',dict['DH'],'\t\t',dict['Encryption'],'\t\t',dict['Hash'],'\t',dict['Mode'],'\t',dict['Life']	
		print '\n'
	
	print '\n'	
	print 'Tunnels'	
	print '-------'
	tunnels = parse.find_objects(r"interface Tunnel")
	for obj in tunnels:
		if obj.re_search_children(r"tunnel mode ipip"):
			#print obj.text.split(' ',1)[1], "operating in IPINIP mode"
			print 'Tunnel', obj.text.split('nel',1)[1], "operating in IPINIP mode"
		if obj.re_search_children(r"tunnel mode gre"):
			#print obj.text.split(' ',1)[1], "operating in GRE mode"
			print 'Tunnel', obj.text.split('nel',1)[1], "operating in GRE mode"
	print '\n'
	'''
	To Add:
	Weak IPSec Authentication Keys
	Weak VPN Authentication Hashing Algorithm Configured:
	'''

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


 
