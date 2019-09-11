#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import os
import json
import glob
import ntpath
import traceback

from pypykatz import logging
from pypykatz.commons.common import UniversalEncoder



class RegistryCMDHelper:
	def __init__(self):
		self.live_keywords = ['registry']
		self.keywords = ['registry']
		
	def add_args(self, parser, live_parser):
		live_group = live_parser.add_parser('registry', help='Get all secrets from registry')
		live_group.add_argument('--json', action='store_true',help = 'Print credentials in JSON format')
		live_group.add_argument('-o', '--outfile', help = 'Save results to file (you can specify --json for json file, or text format will be written)')
		
		group = parser.add_parser('registry', help='Get secrets from registry files')
		group.add_argument('system', help='path to the SYSTEM registry hive')
		group.add_argument('--sam', help='path to the SAM registry hive')
		group.add_argument('--security', help='path to the SECURITY registry hive')
		group.add_argument('--software', help='path to the SOFTWARE registry hive')
		group.add_argument('-o', '--outfile', help = 'Save results to file (you can specify --json for json file, or text format will be written)')
		group.add_argument('--json', action='store_true',help = 'Print credentials in JSON format')
		
	def execute(self, args):
		if len(self.keywords) > 0 and args.command in self.keywords:
			self.run(args)
		
		if len(self.live_keywords) > 0 and args.command == 'live' and args.module in self.live_keywords:
			self.run_live(args)
			
	def process_results(self, results, args):
		if args.outfile:
			results.to_file(args.outfile, args.json)
		else:
			if args.json:
				print(json.dumps(results.to_dict(), cls = UniversalEncoder, indent=4, sort_keys=True))
			else:
				print(str(results))
				
	def run_live(self, args):
		from pypykatz.registry.live_parser import LiveRegistry
		lr = None
		try:
			lr = LiveRegistry.go_live()
		except Exception as e:
			traceback.print_exc()
			logging.debug('Failed to obtain registry secrets via direct registry reading method. Reason: %s' % str(e))
			try:
				from pypykatz.registry.offline_parser import OffineRegistry
				lr = OffineRegistry.from_live_system()
			except Exception as e:
				logging.debug('Failed to obtain registry secrets via filedump method')
		
		if lr is not None:
			self.process_results(lr, args)
		else:
			print('Registry parsing failed!')
			
	def run(self, args):
		from pypykatz.registry.offline_parser import OffineRegistry
		po = OffineRegistry.from_files(args.system, args.sam, args.security, args.software)
		
		self.process_results(po, args)
		