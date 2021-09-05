

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
			parser = NTDSParserConsole(args.systemhive, args.ntdsfile, show_progress = args.progress, outfile = args.outfile)
			await parser.run()

		