#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import io
import os
import re
import struct
import logging
import traceback
import json
import ntpath


from pypykatz.registry.offline_parser import OffineRegistry
from pypykatz.commons.common import UniversalEncoder, hexdump

def main():
	import argparse
	import glob
	
	from pypykatz.utils.crypto.cmdhelper import CryptoCMDHelper
	from pypykatz.ldap.cmdhelper import LDAPCMDHelper
	from pypykatz.kerberos.cmdhelper import KerberosCMDHelper
	from pypykatz.lsadecryptor.cmdhelper import LSACMDHelper
	from pypykatz.registry.cmdhelper import RegistryCMDHelper
	
	cmdhelpers = [CryptoCMDHelper(), LDAPCMDHelper(), KerberosCMDHelper(), LSACMDHelper(), RegistryCMDHelper()]
	

	parser = argparse.ArgumentParser(description='Pure Python implementation of Mimikatz --or at least some parts of it--')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	
	subparsers = parser.add_subparsers(help = 'commands')
	subparsers.required = True
	subparsers.dest = 'command'
	
	live_group = subparsers.add_parser('live', help='Get secrets from live machine')
	live_subparsers = live_group.add_subparsers(help = 'module')
	live_subparsers.required = True
	live_subparsers.dest = 'module'
	
	#this is the new cmd helper formet, in beta mode currently
	for helper in cmdhelpers:
		helper.add_args(subparsers, live_subparsers)
	
	
	live_subparser_process_group = live_subparsers.add_parser('process', help='Process creating/manipulation commands')
	
	live_subparser_process_group.add_argument('cmd', choices=['create'])
	live_subparser_process_group.add_argument('-i','--interactive', action = 'store_true', help = 'Spawns a new interactive process')
	live_subparser_process_group.add_argument('--sid', help = 'Impersonate given SID in new process')
	live_subparser_process_group.add_argument('-c', '--cmdline', help = 'The process to execute. Default: cmd.exe')
	
	live_subparser_token_group = live_subparsers.add_parser('token', help='Token creating/manipulation commands')
	live_subparser_token_group.add_argument('cmd', choices=['list', 'current'])
	live_subparser_token_group.add_argument('-f','--force', action='store_true', help= 'Tries to list as many tokens as possible without SE_DEBUG privilege')
	live_subparser_users_group = live_subparsers.add_parser('users', help='User creating/manipulation commands')
	live_subparser_users_group.add_argument('cmd', choices=['list','whoami'])
	
	live_subparser_dpapi_group = live_subparsers.add_parser('dpapi', help='DPAPI (live) related commands')
	live_subparser_dpapi_group.add_argument('-r','--method_registry', action='store_true', help= 'Getting prekeys from LIVE registry')
	live_subparser_dpapi_group.add_argument('--vpol', help= 'VPOL file')
	live_subparser_dpapi_group.add_argument('--vcred', help= 'VCRED file')
	live_subparser_dpapi_group.add_argument('--cred', help= 'credential file')
	live_subparser_dpapi_group.add_argument('--mkf', help= 'masterkey file')
	
	dpapi_group = subparsers.add_parser('dpapi', help='DPAPI (offline) related commands')
	dpapi_group.add_argument('cmd', choices=['masterkey', 'credential', 'vault'])
	dpapi_group.add_argument('-r', '--method_registry', action='store_true', help= 'Getting prekeys from registry hive files. Using this you will need to also supply system, security and optionally sam switches')
	dpapi_group.add_argument('--system', help= 'Path to SYSTEM hive file')
	dpapi_group.add_argument('--sam', help= 'Path to SAM hive file')
	dpapi_group.add_argument('--security', help= 'Path to SECURITY hive file')
	dpapi_group.add_argument('--vcred', help= 'VCRED file')
	dpapi_group.add_argument('--cred', help= 'credential file')
	dpapi_group.add_argument('--mkf', help= 'masterkey file')
	dpapi_group.add_argument('--key', help= 'Key used for decryption. The usage of this key depends on what other params you supply.')
	dpapi_group.add_argument('--sid', help= 'Key used for decryption. The usage of this key depends on what other params you supply.')
	dpapi_group.add_argument('--password', help= 'Key used for decryption. The usage of this key depends on what other params you supply.')
	
	sake_group = subparsers.add_parser('sake', help='sake')
	
	####### PARSING ARGUMENTS
	
	args = parser.parse_args()
	
	
	###### VERBOSITY
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
	else:
		level = 5 - args.verbose
		logging.basicConfig(level=level)
	
	##### Common obj
	results = {}
	files_with_error = []
	
	for helper in cmdhelpers:
		helper.execute(args)
	
	
	###### Live 
	if args.command == 'live':				
		if args.module == 'process':
			if args.cmd == 'create':
				from pypykatz.commons.winapi.processmanipulator import ProcessManipulator
				pm = ProcessManipulator()
				sid = 'S-1-5-18'
				if args.sid is not None:
					sid = args.sid
				
				if args.cmdline is not None:
					cmdline = args.cmdline
				else:
					#looking for the correct path...
					cmdline = os.environ['ComSpec']
				
				pm.create_process_for_sid(target_sid = sid, cmdline = cmdline, interactive = args.interactive)
				return
				
		elif args.module == 'token':
			from pypykatz.commons.winapi.processmanipulator import ProcessManipulator
			if args.cmd == 'list':
				pm = ProcessManipulator()
				for ti in pm.list_all_tokens(args.force):
					print(str(ti))
				return
				
			if args.cmd == 'current':
				pm = ProcessManipulator()
				token_info = pm.get_current_token_info()
				print(str(token_info))
				return
				
		elif args.module == 'users':
			from pypykatz.commons.winapi.machine import LiveMachine
			
			if args.cmd == 'list':
				lm = LiveMachine()
				users = lm.list_users()
				for sid in users:
					print(str(users[sid]))
					
			elif args.cmd == 'whoami':
				lm = LiveMachine()
				user = lm.get_current_user()
				print(str(user))
				
		elif args.module == 'dpapi':
			from pypykatz.dpapi.dpapi import DPAPI
			
			dpapi = DPAPI()
			#####pre-key section
			if args.method_registry == True:
				dpapi.get_prekeys_form_registry_live()
				
				if not args.mkf:
					raise Exception('Live registry method requires masterkeyfile to be set!')
				
				dpapi.decrypt_masterkey_file(args.mkf)
			
			else:
				dpapi.get_masterkeys_from_lsass_live()
			
			#decryption stuff
			if args.vcred:
				if args.vpol is None:
					raise Exception('for VCRED decryption you must suppliy VPOL file')
				dpapi.decrypt_vpol_file(args.vpol)
				res = dpapi.decrypt_vcrd_file(args.vcred)
				for attr in res:
					for i in range(len(res[attr])):
						if res[attr][i] is not None:
							print('AttributeID: %s Key %s' % (attr.id, i))
							print(hexdump(res[attr][i]))
				
			elif args.vpol:
				key1, key2 = dpapi.decrypt_vpol_file(args.vpol)
				print('VPOL key1: %s' % key1.hex())
				print('VPOL key2: %s' % key2.hex())
				
			elif args.cred:
				cred_blob = dpapi.decrypt_credential_file(args.cred)
				print(cred_blob.to_text())
				
			else:
				#just printing masterkeys
				for guid in dpapi.masterkeys:
					print('GUID: %s MASTERKEY: %s' % (guid, dpapi.masterkeys[guid].hex()))
					
				if len(dpapi.masterkeys) == 0:
					print('Failed to decrypt masterkey')
			
			
	###### DPAPI offline
	elif args.command == 'dpapi':
		from pypykatz.dpapi.dpapi import DPAPI
		
		if args.key is not None:
			key = bytes.fromhex(args.key)
		
		dpapi = DPAPI()
		if args.cmd == 'masterkey':
			if args.mkf is None:
				raise Exception('You need to provide a masterkey file.')
			
			if args.method_registry == True:
				if args.system is None or args.security is None:
					raise Exception('For offline registry parsing you will need to provide SYSTEM and SECURITY hives!')
				
				dpapi.get_prekeys_form_registry_files(args.system, args.security, args.sam)
				dpapi.decrypt_masterkey_file(args.mkf)			
			
			elif args.key is not None:
				dpapi.decrypt_masterkey_file(args.mkf, key)
				
			elif args.sid is not None:
				pw = args.password
				if args.password is None:
					import getpass
					pw = getpass.getpass()
			
				
				dpapi.get_prekeys_from_password(args.sid, pw)
				dpapi.decrypt_masterkey_file(args.mkf)
				
			else:
				raise Exception('For masterkey decryption you must provide either registry hives OR key data OR SID and password')
				
			for guid in dpapi.masterkeys:
				print('GUID %s MASTERKEY %s' % (guid, dpapi.masterkeys[guid].hex()))
			if len(dpapi.masterkeys) == 0:
				print('Failed to decrypt the masterkeyfile!')
		
		elif args.cmd == 'credential':
			if args.key is not None:
				cred_blob = dpapi.decrypt_credential_file(args.cred, key)
				print(cred_blob.to_text())
				
			else:
				if args.method_registry == True:
					if args.system is None or args.security is None:
						raise Exception('For offline registry parsing you will need to provide SYSTEM and SECURITY hives!')
					
					dpapi.get_prekeys_form_registry_files(args.system, args.security, args.sam)
					dpapi.decrypt_masterkey_file(args.mkf, key)
				
				elif args.sid is not None:
					pw = args.password
					if args.password is None:
						import getpass
						pw = getpass.getpass()
					
					dpapi.get_prekeys_from_password(args.sid, pw)
					dpapi.decrypt_masterkey_file(args.mkf, key)
					
				elif args.minidump is not None:
					dpapi.get_masterkeys_from_lsass_dump(args.minidumpfile)
					
				
				cred_blob = dpapi.decrypt_credential_file(args.cred, key)
				print(cred_blob.to_text())
				
		elif args.cmd == 'vault':
			if args.vpol is not None:
				if args.key is not None:
					key1, key2 = dpapi.decrypt_vpol_file(args.vpol, key)
					print('VPOL key1: %s' % key1.hex())
					print('VPOL key2: %s' % key2.hex())
					
				else:
					if args.method_registry == True:
						if args.system is None or args.security is None:
							raise Exception('For offline registry parsing you will need to provide SYSTEM and SECURITY hives!')
						
						dpapi.get_prekeys_form_registry_files(args.system, args.security, args.sam)
						dpapi.decrypt_masterkey_file(args.mkf, key)
					
					elif args.sid is not None:
						pw = args.password
						if args.password is None:
							import getpass
							pw = getpass.getpass()
						
						dpapi.get_prekeys_from_password(args.sid, pw)
						dpapi.decrypt_masterkey_file(args.mkf, key)
						
					elif args.minidump is not None:
						dpapi.get_masterkeys_from_lsass_dump(args.minidumpfile)
				
					key1, key2 = dpapi.decrypt_vpol_file(args.vpol)
					print('VPOL key1: %s' % key1.hex())
					print('VPOL key2: %s' % key2.hex())
					
				if args.vcred is not None:
					res = dpapi.decrypt_vcrd_file(args.vcred)
					for attr in res:
						for i in range(len(res[attr])):
							if res[attr][i] is not None:
								print('AttributeID: %s Key %s' % (attr.id, i))
								print(hexdump(res[attr][i]))
		
			if args.vcred is not None:
				if args.key is not None:
					key1, key2 = dpapi.decrypt_vpol_file(args.vpol, key)
					print('VPOL key1: %s' % key1.hex())
					print('VPOL key2: %s' % key2.hex())
					
				if args.vpol is None:
					raise Exception('VCRED decryption requires a key OR a VPOL file')
	
	###### Sake
	elif args.command == 'sake':
		from pypykatz.utils.sake.sake import Sake
		s = Sake()
		print(s.draw())
					
	
	

if __name__ == '__main__':
	main()