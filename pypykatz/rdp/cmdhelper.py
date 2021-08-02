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
import base64

from pypykatz import logging
from pypykatz.commons.common import UniversalEncoder
from pypykatz.rdp.parser import RDPCredParser



class RDPCMDHelper:
	def __init__(self):
		self.live_keywords = ['rdp']
		self.keywords = ['rdp']
		
	def add_args(self, parser, live_parser):
		live_group = live_parser.add_parser('rdp', help='a')
		live_group.add_argument('--pid', type=int, help = 'Search a specific process PID for RDP creds')
		live_group.add_argument('--all', action='store_true', help = 'Looks for all processes which use the rdp DLL')

		group = parser.add_parser('rdp', help='Parse RDP ceredentials from minidump file. Only WINVER <= Win2012')
		group.add_argument('cmd', choices=['minidump'])
		group.add_argument('memoryfile', help='path to the dump file')

	def execute(self, args):
		if len(self.keywords) > 0 and args.command in self.keywords:
			self.run(args)
		
		if len(self.live_keywords) > 0 and args.command == 'live' and args.module in self.live_keywords:
			self.run_live(args)
		
	def run_live(self, args):
		credparsers = RDPCredParser.go_live(pid = args.pid, all_rdp = args.all)
		for credparser in credparsers:
			for cred in credparser.credentials:
				print(str(cred))
				
	def run(self, args):
		credparsers = RDPCredParser.parse_minidump_file(args.memoryfile)
		for credparser in credparsers:
			for cred in credparser.credentials:
				print(str(cred))