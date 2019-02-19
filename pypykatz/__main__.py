#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import io
import os
import re
import struct
import logging
import traceback
import json
import ntpath


from pypykatz.pypykatz import pypykatz
from pypykatz.commons.common import UniversalEncoder

def main():
	import argparse
	import glob

	parser = argparse.ArgumentParser(description='Pure Python implementation of Mimikatz --or at least some parts of it--')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('--json', action='store_true',help = 'Print credentials in JSON format')
	parser.add_argument('-e','--halt-on-error', action='store_true',help = 'Stops parsing when a file cannot be parsed')
	parser.add_argument('-o', '--outfile', help = 'Save results to file (you can specify --json for json file, or text format will be written)')
	parser.add_argument('-k', '--kerberos-dir', help = 'Save kerberos tickets to a directory.')

	subparsers = parser.add_subparsers(help = 'commands')
	subparsers.required = True
	subparsers.dest = 'command'
	
	minidump_group = subparsers.add_parser('minidump', help='Get secrets from LSASS minidump file')
	minidump_group.add_argument('minidumpfile', help='path to the minidump file or a folder (if -r is set)')
	minidump_group.add_argument('-r', '--recursive', action='store_true', help = 'Recursive parsing')
	minidump_group.add_argument('-d', '--directory', action='store_true', help = 'Parse all dump files in a folder')
	
	
	live_group = subparsers.add_parser('live', help='Get secrets from live machine')
	live_subparsers = live_group.add_subparsers(help = 'module')
	live_subparsers.required = True
	live_subparsers.dest = 'module'
	live_subparser_lsa_group = live_subparsers.add_parser('lsa', help='List all tickets in the file')
	
	rekall_group = subparsers.add_parser('rekall', help='Get secrets from memory dump')
	rekall_group.add_argument('memoryfile', help='path to the memory dump file')
	rekall_group.add_argument('-t','--timestamp_override', type=int, help='enforces msv timestamp override (0=normal, 1=anit_mimikatz)')
	
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
	results = {}
	files_with_error = []
	
	###### Live 
	if args.command == 'live':
		if args.module == 'lsa':
			filename = 'live'
			try:
				mimi = pypykatz.go_live()
				results['live'] = mimi
			except Exception as e:
				files_with_error.append(filename)
				if args.halt_on_error == True:
					raise e
				else:
					print('Exception while dumping LSA credentials from memory.')
					traceback.print_exc()
					pass
	###### Rekall
	elif args.command == 'rekall':
		mimi = pypykatz.parse_memory_dump_rekall(args.memoryfile, args.timestamp_override)
		results['rekall'] = mimi
	
	###### Minidump
	elif args.command == 'minidump':
		if args.directory:
			dir_fullpath = os.path.abspath(args.minidumpfile)
			file_pattern = '*.dmp'
			if args.recursive == True:
				globdata = os.path.join(dir_fullpath, '**', file_pattern)
			else:	
				globdata = os.path.join(dir_fullpath, file_pattern)
				
			logging.info('Parsing folder %s' % dir_fullpath)
			for filename in glob.glob(globdata, recursive=args.recursive):
				logging.info('Parsing file %s' % filename)
				try:
					mimi = pypykatz.parse_minidump_file(filename)
					results[filename] = mimi
				except Exception as e:
					files_with_error.append(filename)
					logging.exception('Error parsing file %s ' % filename)
					if args.halt_on_error == True:
						raise e
					else:
						pass
				
		else:
			logging.info('Parsing file %s' % args.minidumpfile)
			try:
				mimi = pypykatz.parse_minidump_file(args.minidumpfile)
				results[args.minidumpfile] = mimi
			except Exception as e:
				logging.exception('Error while parsing file %s' % args.minidumpfile)
				if args.halt_on_error == True:
					raise e
				else:
					traceback.print_exc()
			

	if args.outfile and args.json:
		with open(args.outfile, 'w') as f:
			json.dump(results, f, cls = UniversalEncoder, indent=4, sort_keys=True)
	
	elif args.outfile:
		with open(args.outfile, 'w') as f:
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
	
	

if __name__ == '__main__':
	main()