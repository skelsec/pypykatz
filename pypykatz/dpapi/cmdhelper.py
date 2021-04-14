from pypykatz.commons.common import UniversalEncoder, hexdump
import argparse
import platform


class DPAPICMDHelper:
	def __init__(self):
		self.live_keywords = ['dpapi']
		self.keywords = ['dpapi']
	
	def add_args(self, parser, live_parser):

		live_subcommand_parser = argparse.ArgumentParser(add_help=False)                                                                                                  
		live_dpapi_subparsers = live_subcommand_parser.add_subparsers(help = 'LIVE DPAPI commands work under the current user context. Except: keys, wifi, chrome')
		live_dpapi_subparsers.required = True
		live_dpapi_subparsers.dest = 'livedpapicommand'
		
		live_keys_parser = live_dpapi_subparsers.add_parser('keys', help = '[ADMIN ONLY]  Dump all local DPAPI related keys. Aggressively. Recommended: use file output. !This takes a while!')
		live_keys_parser.add_argument('--method', choices = ['lsass', 'registry', 'all'], default = 'all', help= 'Where to look for the keys')
		live_keys_parser.add_argument('-o', '--outfile', help= 'Output file base name')

		live_vpol_parser = live_dpapi_subparsers.add_parser('vpol', help = 'Decrypting VPOL file with current user context')
		live_vpol_parser.add_argument('vpolfile', help= 'VPOL file to decrypt')

		live_vcred_parser = live_dpapi_subparsers.add_parser('vcred', help = 'Decrypt VCRED')
		live_vcred_parser.add_argument('vpolfile', help= 'VPOL file to use to decrypt the VCRED file')
		live_vcred_parser.add_argument('vcredfile', help= 'VCRED file to decrypt')
		
		live_cred_parser = live_dpapi_subparsers.add_parser('cred', help = 'Decrypt CRED file')
		live_cred_parser.add_argument('credfile', help= 'CRED file to decrypt')

		
		live_blob_parser = live_dpapi_subparsers.add_parser('blob', help = 'Decrypt raw dpapi blob hex')
		live_blob_parser.add_argument('blob', help= 'blob string in hex format')
		
		live_securestring_parser = live_dpapi_subparsers.add_parser('securestring', help = 'Decrypt securestring hex')
		live_securestring_parser.add_argument('securestring', help= 'securestring in hex format')
		
		live_blobfile_parser = live_dpapi_subparsers.add_parser('blobfile', help = '')
		live_blobfile_parser.add_argument('blobfile', help= 'Decrypt raw dpapi blob in file')
		
		live_securestringfile_parser = live_dpapi_subparsers.add_parser('securestringfile', help = '')
		live_securestringfile_parser.add_argument('securestringfile', help= 'Decrypt securestring from file')

		live_wifi_parser = live_dpapi_subparsers.add_parser('wifi', help = '[ADMIN ONLY] Decrypt stored WIFI passwords')
		live_chrome_parser = live_dpapi_subparsers.add_parser('chrome', help = '[ADMIN ONLY] !TAKES SUPER-LONG! Decrypt all chrome passwords for all users (admin) or for the current user.')


		live_parser.add_parser('dpapi', help='DPAPI (live) related commands. This will use winAPI to decrypt secrets using the current user context.', parents=[live_subcommand_parser])
		

		#offline
		prekey_subcommand_parser = argparse.ArgumentParser(add_help=False)
		dpapi_prekey_subparsers = prekey_subcommand_parser.add_subparsers(help = 'prekey_command')
		dpapi_prekey_subparsers.required = True
		dpapi_prekey_subparsers.dest = 'prekey_command'

		prekey_passwd = dpapi_prekey_subparsers.add_parser('password', help = 'Generate prekeys from password')
		prekey_passwd.add_argument('sid', help='SID of the user')
		prekey_passwd.add_argument('password', help='Password of the user')
		prekey_passwd.add_argument('-o', '--out-file', help= 'Key candidates will be stored in this file. Easier to handle this way in the masterkeyfil command.')

		prekey_nt = dpapi_prekey_subparsers.add_parser('nt', help = 'Generate prekeys from NT hash')
		prekey_nt.add_argument('sid', help='SID of the user')
		prekey_nt.add_argument('nthash', help='NT hash of the user')
		prekey_nt.add_argument('-o', '--out-file', help= 'Key candidates will be stored in this file. Easier to handle this way in the masterkeyfil command.')

		prekey_registry = dpapi_prekey_subparsers.add_parser('registry', help = 'Generate prekeys from registry secrets')
		prekey_registry.add_argument('system', help='SYSTEM hive')
		prekey_registry.add_argument('sam', help='SAM hive')
		prekey_registry.add_argument('security', help='SECURITY hive')
		prekey_registry.add_argument('-o', '--out-file', help= 'Key candidates will be stored in this file. Easier to handle this way in the masterkeyfil command.')
		

		dpapi_group = parser.add_parser('dpapi', help='DPAPI (offline) related commands')
		dpapi_subparsers = dpapi_group.add_subparsers()
		dpapi_subparsers.required = True
		dpapi_subparsers.dest = 'dapi_module'

		dpapi_subparsers.add_parser('prekey', help = 'Prekey generation', parents=[prekey_subcommand_parser])
		
		dpapi_minidump_group = dpapi_subparsers.add_parser('minidump', help='Dump masterkeys and prekeys from minidump file')
		dpapi_minidump_group.add_argument('minidumpfile', help='path to minidump file')
		dpapi_minidump_group.add_argument('-o', '--out-file', help= 'Master and Backup keys will be stored in this file. Easier to handle in other commands.')


		dpapi_masterkey_group = dpapi_subparsers.add_parser('masterkey', help='Decrypt masterkey file')
		dpapi_masterkey_group.add_argument('masterkeyfile', help='path to masterkey file')
		dpapi_masterkey_group.add_argument('prekey', help= 'Path to prekey file, which has multiple decryption key candidates')
		dpapi_masterkey_group.add_argument('-o', '--out-file', help= 'Master and Backup keys will be stored in this file. Easier to handle in other commands.')


		dpapi_credential_group = dpapi_subparsers.add_parser('credential', help='Decrypt credential file')
		dpapi_credential_group.add_argument('mkf', help= 'Keyfile generated by the masterkey -o command.')
		dpapi_credential_group.add_argument('cred', help='path to credential file')

		dpapi_vcred_group = dpapi_subparsers.add_parser('vcred', help='Decrypt vcred file')
		dpapi_vcred_group.add_argument('vcred', help='path to vcred file')
		dpapi_vcred_group.add_argument('--vpolkey', nargs='+', help= 'Key obtained by decrypting the corresponding VPOL file, in hex format. Remember to try both VPOL keys')

		dpapi_vpol_group = dpapi_subparsers.add_parser('vpol', help='Decrypt vpol file')
		dpapi_vpol_group.add_argument('mkf', help= 'Keyfile generated by the masterkey -o command.')
		dpapi_vpol_group.add_argument('vpol', help='path to vpol file')
		
		
		dpapi_securestring_group = dpapi_subparsers.add_parser('securestring', help='Decrypt securestring')
		dpapi_securestring_group.add_argument('mkf', help= 'Keyfile generated by the masterkey -o command.')
		dpapi_securestring_group.add_argument('securestring', help='path to securestring file (hex data expected!), or the securestring in hex form')

		dpapi_blob_group = dpapi_subparsers.add_parser('blob', help='Decrypt blob')
		dpapi_blob_group.add_argument('mkf', help= 'Keyfile generated by the masterkey -o command.')
		dpapi_blob_group.add_argument('blob', help='path to blob file (hex data expected!), or the blob in hex form')

	def execute(self, args):
		if len(self.keywords) > 0 and args.command in self.keywords:
			self.run(args)
		
		if len(self.live_keywords) > 0 and args.command == 'live' and args.module in self.live_keywords:
			self.run_live(args)
	
	def run(self, args):
		from pypykatz.dpapi.dpapi import DPAPI

		dpapi = DPAPI()

		if args.dapi_module == 'prekey':
			if args.prekey_command == 'registry':
				if args.system is None:
					raise Exception('SYSTEM hive must be specified for registry parsing!')
				if args.sam is None and args.security is None:
					raise Exception('Either SAM or SECURITY hive must be supplied for registry parsing! Best to have both.')

				dpapi.get_prekeys_form_registry_files(args.system, args.security, args.sam)
			
			elif args.prekey_command == 'password':
				if args.sid is None:
					raise Exception('SID must be specified for generating prekey in this mode')
				
				pw = args.password
				if args.password is None:
					import getpass
					pw = getpass.getpass()

				dpapi.get_prekeys_from_password(args.sid, password = pw)
			
			elif args.prekey_command == 'nt':
				if args.nthash is None or args.sid is None:
					raise Exception('NT hash and SID must be specified for generating prekey in this mode')

				dpapi.get_prekeys_from_password(args.sid, nt_hash = args.nthash)


			dpapi.dump_pre_keys(args.out_file)


		elif args.dapi_module == 'minidump':
			if args.minidumpfile is None:
				raise Exception('minidump file must be specified for mindiump parsing!')
			
			dpapi.get_masterkeys_from_lsass_dump(args.minidumpfile)
			dpapi.dump_masterkeys(args.out_file)
			if args.out_file is not None:
				dpapi.dump_pre_keys(args.out_file + '_prekeys')
			else:
				dpapi.dump_pre_keys()


		elif args.dapi_module == 'masterkey':
			if args.prekey is None:
				raise Exception('Etieher KEY or path to prekey file must be supplied!')

			dpapi.load_prekeys(args.prekey)
			dpapi.decrypt_masterkey_file(args.masterkeyfile)
			
			if len(dpapi.masterkeys) == 0 and len(dpapi.backupkeys) == 0:
				print('Failed to decrypt the masterkeyfile!')
				return

			dpapi.dump_masterkeys(args.out_file)

		elif args.dapi_module == 'credential':
			dpapi.load_masterkeys(args.mkf)
			cred_blob = dpapi.decrypt_credential_file(args.cred)
			
			print(cred_blob.to_text())

		elif args.dapi_module == 'vpol':
			dpapi.load_masterkeys(args.mkf)
			key1, key2 = dpapi.decrypt_vpol_file(args.vpol)

			print('VPOL key1: %s' % key1.hex())
			print('VPOL key2: %s' % key2.hex())


		elif args.dapi_module == 'vcred':
			if args.vpolkey is None or len(args.vpolkey) == 0:
				raise Exception('VPOL key bust be specified!')
			
			dpapi.vault_keys = [bytes.fromhex(x) for x in args.vpolkey] 
			res = dpapi.decrypt_vcrd_file(args.vcred)
			for attr in res:
				for i in range(len(res[attr])):
					if res[attr][i] is not None:
						print('AttributeID: %s Key %s' % (attr.id, i))
						print(hexdump(res[attr][i]))
						
		elif args.dapi_module == 'securestring':
			dpapi.load_masterkeys(args.mkf)
				
			try:
				bytes.fromhex(args.securestring)
			except Exception as e:
				print('Error! %s' %e)
				dec_sec = dpapi.decrypt_securestring_file(args.securestring)
			else:
				dec_sec = dpapi.decrypt_securestring_hex(args.securestring)
			
			print('HEX: %s' % dec_sec.hex())
			print('STR: %s' % dec_sec.decode('utf-16-le'))

		elif args.dapi_module == 'blob':
			dpapi.load_masterkeys(args.mkf)
				
			try:
				bytes.fromhex(args.blob)
			except Exception as e:
				print('Error! %s' %e)
				dec_sec = dpapi.decrypt_securestring_file(args.blob)
			else:
				dec_sec = dpapi.decrypt_securestring_hex(args.blob)
			
			print('HEX: %s' % dec_sec.hex())
			print('STR: %s' % dec_sec.decode('utf-16-le'))

		

	def run_live(self, args):
		if platform.system().lower() != 'windows':
			raise Exception('Live commands only work on Windows!')

		from pypykatz.dpapi.dpapi import DPAPI	
		dpapi = DPAPI(use_winapi=True)

		if args.livedpapicommand == 'keys':
			from pypykatz.dpapi.dpapi import prepare_dpapi_live	
			
			dpapi = prepare_dpapi_live(args.method)
				
			if args.outfile is not None:
				dpapi.dump_pre_keys(args.outfile + '_prekeys')
				dpapi.dump_masterkeys(args.outfile + '_masterkeys')
			else:
				dpapi.dump_pre_keys()
				dpapi.dump_masterkeys()
			
			return

		elif args.livedpapicommand == 'cred':
			cred_blob = dpapi.decrypt_credential_file(args.credfile)
			print(cred_blob.to_text())
				
		elif args.livedpapicommand == 'vpol':
			key1, key2 = dpapi.decrypt_vpol_file(args.vpolfile)
			print('VPOL key1: %s' % key1.hex())
			print('VPOL key2: %s' % key2.hex())

		elif args.livedpapicommand == 'vcred':
			key1, key2 = dpapi.decrypt_vpol_file(args.vpolfile)
			res = dpapi.decrypt_vcrd_file(args.vcredfile)
			for attr in res:
				for i in range(len(res[attr])):
					if res[attr][i] is not None:
						print('AttributeID: %s Key %s' % (attr.id, i))
						print(hexdump(res[attr][i]))

			
		elif args.livedpapicommand == 'securestring':
			dec_sec = dpapi.decrypt_securestring_hex(args.securestring)
			print('HEX: %s' % dec_sec.hex())
			print('STR: %s' % dec_sec.decode('utf-16-le'))

		elif args.livedpapicommand == 'securestringfile':
			data = args.data[0]
			dec_sec = dpapi.decrypt_securestring_file(data)
			print('HEX: %s' % dec_sec.hex())
			print('STR: %s' % dec_sec.decode('utf-16-le'))

		elif args.livedpapicommand == 'blob':
			dec_sec = dpapi.decrypt_securestring_hex(args.blob)
			print('HEX: %s' % dec_sec.hex())

		elif args.livedpapicommand == 'blobfile':
			dec_sec = dpapi.decrypt_securestring_file(args.blobfile)
			print('HEX: %s' % dec_sec.hex())
			
		elif args.livedpapicommand == 'chrome':
			res = dpapi.decrypt_all_chrome_live()
			for file_path, url, user, password in res['logins']:
				print('file: %s user: %s pass: %s url: %s' % (file_path, user, password, url))
			for file_path, host_key, name, path, value in res['cookies']:
				print('file: %s host_key: %s name: %s path: %s value: %s' % (file_path, host_key, name, path, value))

		elif args.livedpapicommand == 'wifi':
			for wificonfig in dpapi.decrypt_wifi_live():
				print('%s : %s' % (wificonfig['name'], wificonfig['key']))