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

from pypykatz.pypykatz import pypykatz

if __name__ == '__main__':
	import argparse
	import glob

	parser = argparse.ArgumentParser(description='Pure Python implementation of Mimikatz -currently only minidump-')
	parser.add_argument('minidumpfile', help='path to the minidump file or a folder (if -r is set)')
	parser.add_argument('-r', '--recursive', action='store_true', help = 'Recursive parsing')
	parser.add_argument('-d', '--directory', action='store_true', help = 'Parse all dump files in a folder')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('--json', action='store_true',help = 'Print credentials in JSON format')
	parser.add_argument('-o', '--outfile', help = 'Save results to file (you can specify --json for json file, or text format will be written)')
	
	args = parser.parse_args()
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
	else:
		logging.basicConfig(level=1)
	
	if args.directory:
		dir_fullpath = os.path.abspath(args.minidumpfile)
		file_pattern = '*.dmp'
		if args.recursive == True:
			globdata = os.path.join(dir_fullpath, '**', file_pattern)
		else:	
			globdata = os.path.join(dir_fullpath, file_pattern)
		results = {}
		logging.info('Parsing folder %s' % dir_fullpath)
		for filename in glob.glob(globdata, recursive=args.recursive):
			logging.info('Parsing file %s' % filename)
			try:
				mimi = pypykatz.parse_minidump_file(filename)
				results[filename] = mimi
			except Exception as e:
				results[filename] = 'ERROR IN PARSING!'
				logging.warning(e )
				pass
			
		if args.outfile and args.json:
			with open(args.outfile, 'w') as f:
				json.dump(results, f, cls = UniversalEncoder, indent=4, sort_keys=True)
		
		elif args.outfile:
			with open(args.outfile, 'w') as f:
				for result in results:
					f.write('FILE: ======== %s =======' % result)
					
					for luid in results[result].logon_sessions:
						f.write(str(results[result].logon_sessions[luid]))
					
					f.write('== Orphaned credentials ==')
					for cred in results[result].orphaned_creds:
						f.write(str(cred))
				
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
							
					print('== Orphaned credentials ==')
					for cred in results[result].orphaned_creds:
						print(str(cred))
			
	else:
		logging.info('Parsing file %s' % args.minidumpfile)
		mimi = pypykatz.parse_minidump_file(args.minidumpfile)
		
		if args.outfile and args.json:
			with open(args.outfile, 'w') as f:
				json.dump(mimi, f, cls = UniversalEncoder, indent=4, sort_keys=True)
		elif args.outfile:
			with open(args.outfile, 'w') as f:
				f.write('FILE: ======== %s =======' % result)
					
				for luid in mimi.logon_sessions:
					f.write(str(mimi.logon_sessions[luid]))
					
				if len(mimi.orphaned_creds) != 0:
					f.write('== Orphaned credentials ==')
					for cred in mimi.orphaned_creds:
						f.write(str(cred))
						
									
		elif args.json:
			print(json.dumps(mimi, cls = UniversalEncoder, indent=4, sort_keys=True))
				
		else:
			for luid in mimi.logon_sessions:
				print(str(mimi.logon_sessions[luid]))
				
			if len(mimi.orphaned_creds) != 0:
				print('== Orphaned credentials ==')
				for cred in mimi.orphaned_creds:
					print(str(cred))