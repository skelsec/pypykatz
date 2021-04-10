#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import os
import logging

def main():
	import argparse
	import glob
	
	from pypykatz.utils.crypto.cmdhelper import CryptoCMDHelper
	from pypykatz.ldap.cmdhelper import LDAPCMDHelper
	from pypykatz.kerberos.cmdhelper import KerberosCMDHelper
	from pypykatz.lsadecryptor.cmdhelper import LSACMDHelper
	from pypykatz.registry.cmdhelper import RegistryCMDHelper
	from pypykatz.remote.cmdhelper import RemoteCMDHelper
	from pypykatz.dpapi.cmdhelper import DPAPICMDHelper
	
	cmdhelpers = [LSACMDHelper(), RegistryCMDHelper(), CryptoCMDHelper(), KerberosCMDHelper(), RemoteCMDHelper(), DPAPICMDHelper(), LDAPCMDHelper()]
	
	try:
		from pypykatz.smb.cmdhelper import SMBCMDHelper
		cmdhelpers.append(SMBCMDHelper())
	except Exception as e:
		print(e)
		pass

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

	version_group = subparsers.add_parser('version', help='version')
	banner_group = subparsers.add_parser('banner', help='banner')
	logo_group = subparsers.add_parser('logo', help='logo')
	
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

	elif args.command == 'version':
		from pypykatz._version import __version__
		print(__version__)
	
	elif args.command == 'banner':
		from pypykatz._version import __banner__
		print(__banner__)
	
	elif args.command == 'logo':
		from pypykatz._version import __logo__, __logo_color__
		print(__logo_color__)
		print(__logo__)
					
	
	

if __name__ == '__main__':
	main()
