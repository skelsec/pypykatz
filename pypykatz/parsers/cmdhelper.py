

#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import asyncio
import platform
from tqdm import tqdm

async def flush_buffer(buffer, outfile_handle = None):
	try:
		if outfile_handle is not None:
			res = ''
			for secret in buffer:
				try:
					res += str(secret)
				except:
					continue
			outfile_handle.write(res)
		else:
			for secret in buffer:
				try:
					print(str(secret))
				except:
					continue
		
		buffer = []
		return True, None
	except Exception as e:
		return None, e

class ParsersCMDHelper:
	def __init__(self):
		self.live_keywords = ['parser']
		self.keywords = ['parser']
		
	def add_args(self, parser, live_parser):
		parser_group = parser.add_parser('parser', help='SMB related commands')
		parser_subparsers = parser_group.add_subparsers()
		parser_subparsers.required = True
		parser_subparsers.dest = 'parser_module'

		ntds_group = parser_subparsers.add_parser('ntds', help='NTDS.dit file parser, extracting secrets')
		ntds_group.add_argument('ntdsfile', help="NTDS.dit file")
		ntds_group.add_argument('systemhive', help="SYSTEM hive file or the Bootkey(in hex). This is needed to decrypt the secrets")
		ntds_group.add_argument('-p', '--progress', action='store_true', help="Show progress bar. Please use this only if you also specified an output file.")
		ntds_group.add_argument('-o', '--outfile', help='Output file. If omitted secrets will be printed to STDOUT')
		ntds_group.add_argument('--strict', action='store_true', help='Strict parsing. Fails on errors')
		ntds_group.add_argument('--no-history', action='store_true', help='Do not parse history')
		
		
	def execute(self, args):
		if args.command in self.keywords:
			asyncio.run(self.run(args))
		
		if len(self.live_keywords) > 0 and args.command == 'live' and args.module in self.live_keywords:
			asyncio.run(self.run_live(args))
			
			
	async def run_live(self, args):
		if platform.system().lower() != 'windows':
			raise Exception('Live commands only work on Windows!')
			
	async def run(self, args):
		if args.parser_module == 'ntds':
			from aesedb.examples.ntdsparse import NTDSParserConsole
			ntdscon = NTDSParserConsole(
				args.systemhive,
				args.ntdsfile,
				ignore_errors=args.strict,
				with_history=not args.no_history
			)

			buffer = []
			buffer_size = 1000
			total = await ntdscon.get_total_rows()
			if args.progress is True:
				pbar     = tqdm(desc='JET table parsing ', total=total, unit='records', miniters= total//200 ,position=0)
				pbar_sec = tqdm(desc='User secrets found', unit = '', miniters=buffer_size//10 ,position=1)

			outfile_handle = None
			if args.outfile is not None:
				outfile_handle = open(args.outfile, 'w', newline = '')

			async for secret, err in ntdscon.get_secrets():
				if err is not None:
					raise err

				if args.progress is True:
					pbar.update()
					
				if secret is None:
					continue
					
				if args.progress is True:
					pbar_sec.update()
					

				buffer.append(secret)
				if len(buffer) > buffer_size:
					_, err = await flush_buffer(buffer, outfile_handle)
					buffer = []
					if err is not None:
						raise err

				
			_, err = await flush_buffer(buffer, outfile_handle)
			buffer = []
			if err is not None:
				raise err


			#parser = NTDSParserConsole(args.systemhive, args.ntdsfile, show_progress = args.progress, outfile = args.outfile)
			#await parser.run()

		