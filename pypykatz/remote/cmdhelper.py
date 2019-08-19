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



class RemoteCMDHelper:
	def __init__(self):
		self.live_keywords = ['share','session','localgroup']
		self.keywords = [] #['remote'] no yet implemented
		
	def add_args(self, parser, live_parser):
		live_group = live_parser.add_parser('share', help='Remote share relted operations')
		live_group.add_argument('--json', action='store_true',help = 'Print credentials in JSON format')
		live_group.add_argument('-o', '--outfile', help = 'Save results to file (you can specify --json for json file, or text format will be written)')
		live_group.add_argument('cmd', choices=['enum'])
		live_group.add_argument('-f', '--target-file', help = 'Targets file, one per line')
		live_group.add_argument('-t', '--target', action='append', help = 'Target to check. Stackable.')
		live_group.add_argument('--timeout', type=int, help = 'Pre-check timeout.')
		live_group.add_argument('--disable-pre-check', action='store_true',help = 'Disables pre-check to see if the remote destination is alive. Will make enumeration take years!')
		
		live_group = live_parser.add_parser('session', help='Remote user sessions related operations')
		live_group.add_argument('--json', action='store_true',help = 'Print credentials in JSON format')
		live_group.add_argument('-o', '--outfile', help = 'Save results to file (you can specify --json for json file, or text format will be written)')
		live_group.add_argument('cmd', choices=['enum'])
		live_group.add_argument('-f', '--target-file', help = 'Targets file, one per line')
		live_group.add_argument('-t', '--target', action='append', help = 'Target to check. Stackable.')
		live_group.add_argument('--timeout', type=int, help = 'Pre-check timeout.')
		live_group.add_argument('--disable-pre-check', action='store_true',help = 'Disables pre-check to see if the remote destination is alive. Will make enumeration take years!')
		
		live_group = live_parser.add_parser('localgroup', help='Remote localgroup related operations')
		live_group.add_argument('--json', action='store_true',help = 'Print credentials in JSON format')
		live_group.add_argument('-o', '--outfile', help = 'Save results to file (you can specify --json for json file, or text format will be written)')
		live_group.add_argument('cmd', choices=['enum'])
		live_group.add_argument('-f', '--target-file', help = 'Targets file, one per line')
		live_group.add_argument('-t', '--target', action='append', help = 'Target to check. Stackable.')
		live_group.add_argument('--timeout', type=int, help = 'Pre-check timeout.')
		live_group.add_argument('--disable-pre-check', action='store_true',help = 'Disables pre-check to see if the remote destination is alive. Will make enumeration take years!')
		live_group.add_argument('-g', '--group', action='append', help = 'Localgroup name to look for. Stackable.')
		
		
		#group = parser.add_parser('registry', help='Get secrets from registry files')
		#group.add_argument('system', help='path to the SYSTEM registry hive')
		#group.add_argument('--sam', help='path to the SAM registry hive')
		#group.add_argument('--security', help='path to the SECURITY registry hive')
		#group.add_argument('--software', help='path to the SOFTWARE registry hive')
		#group.add_argument('-o', '--outfile', help = 'Save results to file (you can specify --json for json file, or text format will be written)')
		#group.add_argument('--json', action='store_true',help = 'Print credentials in JSON format')
		
	def execute(self, args):
		if len(self.keywords) > 0 and args.command in self.keywords:
			self.run(args)
		
		if len(self.live_keywords) > 0 and args.command == 'live' and args.module in self.live_keywords:
			self.run_live(args)
			
	def process_results(self, results, args):
		pass
				
	def run_live(self, args):
		if args.module == 'share':
			if args.cmd == 'enum':
				from pypykatz.remote.live.share.enumerator import ShareEnumerator
				
				se = ShareEnumerator()
				if args.target_file:
					se.load_targets_file(args.target_file)
				
				if args.target:
					se.load_tagets(args.target)
					
				if len(se.hosts) == 0:
					raise Exception('No targets loaded!')
					
				if args.timeout:
					se.timeout = args.timeout
				
				se.pre_check = True
				if args.disable_pre_check:
					se.pre_check = False
				
				se.to_json = args.json
				if args.outfile:
					se.out_file = args.outfile
		
					
				se.run()
		
		elif args.module == 'session':
			if args.cmd == 'enum':
				from pypykatz.remote.live.session.enumerator import SessionMonitor
				
				se = SessionMonitor()
				if args.target_file:
					se.load_targets_file(args.target_file)
				
				if args.target:
					se.load_tagets(args.target)
					
				if len(se.hosts) == 0:
					raise Exception('No targets loaded!')
					
				if args.timeout:
					se.timeout = args.timeout
				
				se.pre_check = True
				if args.disable_pre_check:
					se.pre_check = False
					
				se.to_json = args.json
				if args.outfile:
					se.out_file = args.outfile
					
				se.run()
			
		elif args.module == 'localgroup':
			if args.cmd == 'enum':
				from pypykatz.remote.live.localgroup.enumerator import LocalGroupEnumerator
				
				se = LocalGroupEnumerator()
				if args.target_file:
					se.load_targets_file(args.target_file)
				
				if args.target:
					se.load_tagets(args.target)
					
				if len(se.hosts) == 0:
					raise Exception('No targets loaded!')
					
				if args.timeout:
					se.timeout = args.timeout
				
				
				se.groups = ['Remote Desktop Users','Administrators','Distributed COM Users']
				if args.group:
					se.groups = args.group
				
				se.pre_check = True
				if args.disable_pre_check:
					se.pre_check = False
					
				se.to_json = args.json
				if args.outfile:
					se.out_file = args.outfile
					
				se.run()
			
	def run(self, args):
		pass
		