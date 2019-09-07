#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

class CryptoCMDHelper:
	def __init__(self):
		self.live_keywords = []
		self.keywords = ['nt','lm','dcc','dcc2','gppass']
		
	def add_args(self, parser, live_parser):
		group = parser.add_parser('nt', help='Generates NT hash of the password')
		group.add_argument('password', help= 'Password to be hashed')	
		
		group = parser.add_parser('lm', help='Generates LM hash of the password')
		group.add_argument('password', help= 'Password to be hashed')
		
		group = parser.add_parser('dcc', help='Generates DCC v1 (domain cached credentials version 1) hash of the password')
		group.add_argument('username', help= 'username')
		group.add_argument('password', help= 'Password to be hashed')
		
		group = parser.add_parser('dcc2', help='Generates DCC v2 (domain cached credentials version 2) hash of the password')
		group.add_argument('username', help= 'username')
		group.add_argument('password', help= 'Password to be hashed')
		group.add_argument('-i','--iteration-count', type = int, default=10240, help= 'iteration-count')
		
		group = parser.add_parser('gppass', help='Decrypt GP passwords')
		group.add_argument('enc', help='Encrypted password string')
		
	def execute(self, args):
		if args.command in self.keywords:
			self.run(args)
		if len(self.live_keywords) > 0 and args.command == 'live' and args.module in self.live_keywords:
			self.run_live(args)
			
	def run(self, args):
		from pypykatz.utils.crypto.winhash import NT, LM, MSDCC, MSDCCv2
		from pypykatz.utils.crypto.gppassword import gppassword
		if args.command == 'nt':
			print(NT(args.password).hex())
		
		elif args.command == 'lm':
			print(LM(args.password).hex())
			
		elif args.command == 'dcc':
			print(MSDCC(args.username, args.password).hex())
			
		elif args.command == 'dcc2':
			print(MSDCCv2(args.username, args.password, args.iteration_count).hex())
			
		elif args.command == 'gppass':
			print(gppassword(args.enc))
		