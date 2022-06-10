#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from pypykatz.rdp.parser import RDPCredParser



class RDPCMDHelper:
	def __init__(self):
		self.live_keywords = ['rdp']
		self.keywords = ['rdp']
		
	def add_args(self, parser, live_parser):
		# live
		live_group = live_parser.add_parser('rdp', help='a')
		live_rdp_subparsers = live_group.add_subparsers()
		live_rdp_subparsers.required = True
		live_rdp_subparsers.dest = 'live_rdp_module'

		live_logonpasswords_group = live_rdp_subparsers.add_parser('logonpasswords', help='Parse RDP credentials (SERVER side)')
		live_logonpasswords_group.add_argument('--pid', type=int, help = 'Search a specific process PID for RDP creds')
		live_logonpasswords_group.add_argument('--all', action='store_true', help = 'Looks for all processes which use the rdp DLL rdpcorets.dll')

		live_mstsc_group = live_rdp_subparsers.add_parser('mstsc', help='Parse RDP credentials (CLIENT side)')
		live_mstsc_group.add_argument('--pid', type=int, help = 'Search a specific process PID for RDP creds')
		live_mstsc_group.add_argument('--all', action='store_true', help = 'Looks for all processes which use the rdp DLL mstscax.dll')

		# offline
		group = parser.add_parser('rdp', help='Parse RDP credentials from minidump file')
		rdp_subparsers = group.add_subparsers()
		rdp_subparsers.required = True
		rdp_subparsers.dest = 'rdp_module'

		logonpasswords_group = rdp_subparsers.add_parser('logonpasswords', help='Parse RDP credentials (SERVER side) from minidump file. Plain-text passwords only for WINVER <= Win2012')
		logonpasswords_group.add_argument('cmd', choices=['minidump'])
		logonpasswords_group.add_argument('memoryfile', help='path to the dump file')

		mstsc_group = rdp_subparsers.add_parser('mstsc', help='Parse RDP credentials (CLIENT side) from minidump file. Unable to recover plain-text passwords offline.')
		mstsc_group.add_argument('cmd', choices=['minidump'])
		mstsc_group.add_argument('memoryfile', help='path to the dump file')

	def execute(self, args):
		if len(self.keywords) > 0 and args.command in self.keywords:
			self.run(args)
		
		if len(self.live_keywords) > 0 and args.command == 'live' and args.module in self.live_keywords:
			self.run_live(args)
		
	def run_live(self, args):
		credparsers = RDPCredParser.go_live(pid = args.pid, all_rdp = args.all, live_rdp_module = args.live_rdp_module)
		for credparser in credparsers:
			for cred in credparser.credentials:
				print(str(cred))
				
	def run(self, args):
		credparsers = RDPCredParser.parse_minidump_file(args.memoryfile, args.rdp_module)
		for credparser in credparsers:
			for cred in credparser.credentials:
				print(str(cred))