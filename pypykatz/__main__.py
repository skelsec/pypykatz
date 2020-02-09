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
	#from pypykatz.ldap.cmdhelper import LDAPCMDHelper
	from pypykatz.kerberos.cmdhelper import KerberosCMDHelper
	from pypykatz.lsadecryptor.cmdhelper import LSACMDHelper
	from pypykatz.registry.cmdhelper import RegistryCMDHelper
	from pypykatz.remote.cmdhelper import RemoteCMDHelper
	
	cmdhelpers = [LSACMDHelper(), RegistryCMDHelper(), CryptoCMDHelper(), KerberosCMDHelper(), RemoteCMDHelper()] #LDAPCMDHelper(),
	

	parser = argparse.ArgumentParser(description='Pure Python implementation of Mimikatz --and more--')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	
	subparsers = parser.add_subparsers(help = 'commands')
	subparsers.required = True
	subparsers.dest = 'command'
	
	live_group = subparsers.add_parser('live', help='Get secrets from live machine')
	live_subparsers = live_group.add_subparsers()
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
	dpapi_subparsers = dpapi_group.add_subparsers()
	dpapi_subparsers.required = True
	dpapi_subparsers.dest = 'dapi_module'

	dpapi_prekey_group = dpapi_subparsers.add_parser('prekey', help='Obtains keys for masterkey decryption. Sources can be registry hives file or plaintext password and SID or NT hash and SID')
	dpapi_prekey_group.add_argument('keysource', choices=['registry', 'password', 'nt'], help = 'Define what type of input you want to parse')
	dpapi_prekey_group.add_argument('-o', '--out-file', help= 'Key candidates will be stored in this file. Easier to handle this way in the masterkeyfil command.')
	dpapi_prekey_group.add_argument('--system', help= '[registry] Path to SYSTEM hive file')
	dpapi_prekey_group.add_argument('--sam', help= '[registry] Path to SAM hive file')
	dpapi_prekey_group.add_argument('--security', help= '[registry] Path to SECURITY hive file')
	dpapi_prekey_group.add_argument('--sid', help= '[password and nt] Key used for decryption. The usage of this key depends on what other params you supply.')
	dpapi_prekey_group.add_argument('--password', help= '[password] Plaintext passowrd of the user. Used together with SID')
	dpapi_prekey_group.add_argument('--nt', help= '[nt] NT hash of the user password. Used together with SID. !!Succsess not guaranteed!!')
	
	dpapi_minidump_group = dpapi_subparsers.add_parser('minidump', help='Dump masterkeys from minidump file')
	dpapi_minidump_group.add_argument('minidumpfile', help='path to minidump file')

	dpapi_mastekey_group = dpapi_subparsers.add_parser('masterkey', help='Decrypt masterkey file')
	dpapi_mastekey_group.add_argument('mkf', help='path to masterkey file')
	dpapi_mastekey_group.add_argument('--key', help= 'Key used for decryption, in hex format')
	dpapi_mastekey_group.add_argument('--prekey', help= 'Path to prekey file, which has multiple decryption key candidates')
	dpapi_mastekey_group.add_argument('-o', '--out-file', help= 'Master and Backup keys will be stored in this file. Easier to handle in other commands.')


	dpapi_credential_group = dpapi_subparsers.add_parser('credential', help='Decrypt credential file')
	dpapi_credential_group.add_argument('cred', help='path to credential file')
	dpapi_credential_group.add_argument('--masterkey', help= 'Masterkey used for decryption, in hex format')
	dpapi_credential_group.add_argument('-m', '--mkb-file', help= 'Keyfile generated by the masterkey -o command.')

	dpapi_vcred_group = dpapi_subparsers.add_parser('vcred', help='Decrypt vcred file')
	dpapi_vcred_group.add_argument('vcred', help='path to vcred file')
	dpapi_vcred_group.add_argument('--vpolkey', help= 'Key obtained by decrypting the corresponding VPOL file, in hex format. Remember to try both VPOL keys')

	dpapi_vpol_group = dpapi_subparsers.add_parser('vpol', help='Decrypt vpol file')
	dpapi_vpol_group.add_argument('vpol', help='path to vpol file')
	dpapi_vpol_group.add_argument('--masterkey', help= 'Masterkey used for decryption, in hex format')
	dpapi_vpol_group.add_argument('-m', '--mkb-file', help= 'Keyfile generated by the masterkey -o command.')
	
	sake_group = subparsers.add_parser('sake', help='sake')
	version_group = subparsers.add_parser('version', help='version')
	banner_group = subparsers.add_parser('banner', help='banner')
	
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
	#results = {}
	#files_with_error = []
	
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

		dpapi = DPAPI()

		if args.dapi_module == 'prekey':
			if args.keysource == 'registry':
				if args.system is None:
					raise Exception('SYSTEM hive must be specified for registry parsing!')
				if args.sam is None and args.security is None:
					raise Exception('Either SAM or SECURITY hive must be supplied for registry parsing! Best to have both.')

				dpapi.get_prekeys_form_registry_files(args.system, args.security, args.sam)
			
			elif args.keysource == 'password':
				if args.sid is None:
					raise Exception('SID must be specified for generating prekey in this mode')
				
				pw = args.password
				if args.password is None:
					import getpass
					pw = getpass.getpass()

				dpapi.get_prekeys_from_password(args.sid, password = pw)
			
			elif args.keysource == 'nt':
				if args.nt is None or args.sid is None:
					raise Exception('NT hash and SID must be specified for generating prekey in this mode')

				dpapi.get_prekeys_from_password(args.sid, nt_hash = args.nt)


			dpapi.dump_pre_keys(args.out_file)


		elif args.dapi_module == 'minidump':
			if args.minidumpfile is None:
				raise Exception('minidump file must be specified for mindiump parsing!')
			
			dpapi.get_masterkeys_from_lsass_dump(args.minidumpfile)
			dpapi.dump_masterkeys(args.out_file)


		elif args.dapi_module == 'masterkey':
			if args.key is None and args.prekey is None:
				raise Exception('Etieher KEY or path to prekey file must be supplied!')

			if args.prekey:
				dpapi.load_pre_keys(args.prekey)
				dpapi.decrypt_masterkey_file(args.mkf)

			if args.key:
				dpapi.decrypt_masterkey_file(args.mkf, bytes.fromhex(args.key))
			
			if len(dpapi.masterkeys) == 0 and len(dpapi.backupkeys) == 0:
				print('Failed to decrypt the masterkeyfile!')
				return

			dpapi.dump_masterkeys(args.out_file)

		elif args.dapi_module == 'credential':
			if args.masterkey is None and args.mkb_file is None:
				raise Exception('Either masterkey or pre-generated MKB file must be specified')

			if args.mkb_file is not None:
				dpapi.load_masterkeys(args.mkb_file)
				cred_blob = dpapi.decrypt_credential_file(args.cred)
			else:
				cred_blob = dpapi.decrypt_credential_file(args.cred, args.masterkey)
			
			print(cred_blob.to_text())

		elif args.dapi_module == 'vpol':
			if args.masterkey is None and args.mkb_file is None:
				raise Exception('Either masterkey or pre-generated MKB file must be specified')

			if args.mkb_file is not None:
				dpapi.load_masterkeys(args.mkb_file)
				key1, key2 = dpapi.decrypt_vpol_file(args.vpol)
			else:
				key1, key2 = dpapi.decrypt_vpol_file(args.vpol, args.masterkey)

			
			print('VPOL key1: %s' % key1.hex())
			print('VPOL key2: %s' % key2.hex())


		elif args.dapi_module == 'vcred':
			if args.vpolkey is None:
				raise Exception('VPOL key bust be specified!')
				
			res = dpapi.decrypt_vpol_file(args.vcred, args.vpolkey)
			for attr in res:
				for i in range(len(res[attr])):
					if res[attr][i] is not None:
						print('AttributeID: %s Key %s' % (attr.id, i))
						print(hexdump(res[attr][i]))
	
	###### Sake
	elif args.command == 'sake':
		from pypykatz.utils.sake.sake import Sake
		s = Sake()
		print(s.draw())

	elif args.command == 'version':
		from pypykatz._version import __version__
		print(__version__)
	
	elif args.command == 'banner':
		from pypykatz._version import __banner__
		print(__banner__)
					
	
	

if __name__ == '__main__':
	main()
