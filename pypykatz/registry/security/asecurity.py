#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import hashlib
import hmac
from pypykatz.registry.sam.structures import *
from pypykatz.crypto.RC4 import RC4
from pypykatz.crypto.aes import AESModeOfOperationCBC,AESModeOfOperationECB, Decrypter
from pypykatz.crypto.des import *


#####
from pypykatz.registry.security.structures import *
from pypykatz.registry.security.common import *
from pypykatz.registry import logger
from pypykatz.commons.common import hexdump

#
# The SECURITY hive holds all the domain-cached-credentials for the domain users who logged in to the machine
# It also holds the machine account's password in an encrypted form
#
# The LSA secrets also stored here, but their format is not always documented, 
# as this functionality can be used by any service that wants to stroe some secret information

class SECURITY:
	def __init__(self, security_hive, bootkey):
		self.hive = security_hive
		self.bootkey = bootkey
		
		self.dcc_iteration_count = 10240
		self.lsa_secret_key_vista_type = True
		
		self.lsa_key = None
		self.NKLM_key = None
		
		self.dcc_hashes = []
		self.cached_secrets = []
	
	@staticmethod
	def sha256_multi(key, value, rounds = 1000):
		ctx = hashlib.sha256(key)
		for _ in range(rounds):
			ctx.update(value)
		return ctx.digest()
		
	def decrypt_lsa_key(self, data):
		logger.debug('[SECURITY] Decrypting LSA key...')
		if self.lsa_secret_key_vista_type is True:
			record = LSA_SECRET.from_bytes(data)
			key = SECURITY.sha256_multi(self.bootkey, record.data[:32])
			secret_dec = b''
			cipher = AESModeOfOperationECB(key)
			n = 16
			for block in [record.data[32:][i:i+n] for i in range(0, len(record.data[32:]), n)]:  #terrible, terrible workaround
				if len(block) < n:
					block += b'\x00' * (n - len(block))
				secret_dec += cipher.decrypt(block)
			record = LSA_SECRET_BLOB.from_bytes(secret_dec)
			self.lsa_key = record.secret[52:][:32]
		
		else:
			ctx = hashlib.md5(self.bootkey)
			for i in range(1000):
				ctx.update(data[60:76])
			
			cipher = RC4(ctx.digest())
			record = cipher.decrypt(data[12:60])
			self.lsa_key = record[0x10:0x20]
		
		logger.debug('[SECURITY] LSA key value: %s' % self.lsa_key.hex())
		return self.lsa_key
			
		
	async def get_lsa_key(self):
		logger.debug('[SECURITY] Fetching LSA key...')
		value = await self.hive.get_value('Policy\\PolEKList\\default', False)
		if value is None:
			value = await self.hive.get_value('Policy\\PolSecretEncryptionKey\\default', False)
			if not value:
				logger.debug('[SECURITY] LSA key not found!')
				return None
			
			self.lsa_secret_key_vista_type = False
			logger.debug('[SECURITY] LSA secrets default to VISTA type')
		
		return self.decrypt_lsa_key(value[1])
		
		
	def decrypt_secret(self, key, value):
		dec_blob = b''
		enc_size = int.from_bytes(value[:4], 'little', signed = False)
		value = value[len(value) - enc_size:]
		t_key = key
		for _ in range(0, len(value), 8):
			enc_blob = value[:8]
			des_key = expand_DES_key(t_key[:7])
			ctx = des(des_key)
			dec_blob += ctx.decrypt(enc_blob)
			t_key = t_key[7:]
			value = value[8:]
			if len(t_key) < 7:
				t_key = key[len(t_key) : ]
			
		secret = LSA_SECRET_XP.from_bytes(dec_blob)
		return secret.secret
		
	async def get_NKLM_key(self):
		logger.debug('[SECURITY] Fetching NK$LM key...')
		if self.lsa_key is None:
			await self.get_lsa_key()
			
		value = await self.hive.get_value('Policy\\Secrets\\NL$KM\\CurrVal\\default')
		if value is None:
			logger.error('[SECURITY] Could not find NL$KM in registry')
			raise Exception('Could not find NL$KM in registry :(')
			
		if self.lsa_secret_key_vista_type is True:
			self.NKLM_key = b''
			record = LSA_SECRET.from_bytes(value[1])
			key = SECURITY.sha256_multi(self.lsa_key, record.data[:32])
			cipher = AESModeOfOperationECB(key)
			n = 16
			for block in [record.data[32:][i:i+n] for i in range(0, len(record.data[32:]), n)]:  #terrible, terrible workaround
				if len(block) < n:
					block += b'\x00' * (16 - len(block))
				self.NKLM_key += cipher.decrypt(block)
			
		else:
			self.NKLM_key = self.decrypt_secret(self.lsa_key, value[1])
		
		logger.debug('[SECURITY] NL$KM key: %s' % self.NKLM_key.hex())
		return self.NKLM_key
		
	def __pad(self, data):
		if (data & 0x3) > 0:
			return data + (data & 0x3)
		else:
			return data
		
	async def dump_dcc(self):
		logger.debug('[SECURITY] dump_dcc invoked')
		cache_reg = await self.hive.find_key('Cache', False)
		if cache_reg is None:
			logger.debug('[SECURITY] No DCC secrets found')
			return
		values = await self.hive.list_values(cache_reg)
		
		if values == []:
			logger.debug('[SECURITY] No DCC secrets found')
			return
			
		if b'NL$Control' in values:
			values.remove(b'NL$Control')
			
		if b'NL$IterationCount' in values:
			logger.debug('[SECURITY] DCC Setting iteration count')
			values.remove(b'NL$IterationCount')
			record = await self.hive.get_value('Cache\\NL$IterationCount')
			record = record[1]
			if record > 10240:
				self.dcc_iteration_count = record & 0xfffffc00
			else:
				self.dcc_iteration_count = record * 1024
				
		
		await self.get_lsa_key()
		await self.get_NKLM_key()
		
		for value in values:
			logger.debug('[SECURITY] DCC Checking value: %s' % value)
			record_data = await self.hive.get_value('Cache\\%s' % value.decode())
			record_data = record_data[1]
			record = NL_RECORD.from_bytes(record_data)
			
			if record.IV != b'\x00'*16:
				if record.Flags & 1 == 1:
					# Encrypted
					if self.lsa_secret_key_vista_type is True:
						plaintext = b''
						cipher = AESModeOfOperationCBC(self.NKLM_key[16:32], iv = record.IV)
						n = 16
						for block in [record.EncryptedData[i:i+n] for i in range(0, len(record.EncryptedData), n)]:  #terrible, terrible workaround
							if len(block) < 16:
								block += b'\x00' * (16 - len(block))
							plaintext += cipher.decrypt(block)
							
					else:
						key = hmac.new(self.NKLM_key,record.IV).digest()
						cipher = RC4(key)
						plaintext = cipher.decrypt(record.EncryptedData)
						
				else:
					# Plain! Until we figure out what this is, we skip it
					#plainText = record['EncryptedData']
					logger.debug('[SECURITY] DCC Skipping value %s, unknown formet' % value)
					continue
				
				
				dcc_hash = plaintext[:0x10]
				blob = io.BytesIO(plaintext[0x48:])
				username = blob.read(record.UserLength).decode('utf-16-le')
				blob.seek(self.__pad(record.UserLength) + self.__pad(record.DomainNameLength))
				domain = blob.read(record.DnsDomainNameLength).decode('utf-16-le')
				
				version = 2 if self.lsa_secret_key_vista_type is True else 1
				secret = LSADCCSecret(version, domain, username, dcc_hash, iteration = self.dcc_iteration_count)
				self.dcc_hashes.append(secret)
				
		return self.dcc_hashes	
				
	async def get_secrets(self):
		logger.debug('[SECURITY] get_secrets')
		await self.get_lsa_key()
		
		await self.dump_dcc()
		
		# Let's first see if there are cached entries
		keys = await self.hive.enum_key('Policy\\Secrets')
		if keys is None:
			logger.debug('[SECURITY] No cached secrets found in hive')
			return
			
		if b'NL$Control' in keys:
			keys.remove(b'NL$Control')
		
		for key_name in keys:
			for vl in ['CurrVal', 'OldVal']:
				key_path = 'Policy\\Secrets\\{}\\{}\\default'.format(key_name,vl)
				logger.debug('[SECURITY] Parsing secrets in %s' % key_path)
				v = await self.hive.get_value(key_path, False)
				if v and v[1] != 0:
					logger.log(1, '[SECURITY] Key %s Value %s' % (key_path, v[1]))
					if self.lsa_secret_key_vista_type is True:
						record = LSA_SECRET.from_bytes(v[1])
						key = SECURITY.sha256_multi(self.lsa_key, record.data[:32])
						secret_dec = b''
						cipher = AESModeOfOperationECB(key)
						n = 16
						for block in [record.data[32:][i:i+n] for i in range(0, len(record.data[32:]), n)]:  #terrible, terrible workaround
							if len(block) < n:
								block += b'\x00' * (n - len(block))
							secret_dec += cipher.decrypt(block)
						record = LSA_SECRET_BLOB.from_bytes(secret_dec)
						dec_blob = record.secret
						
					else:
						dec_blob = self.decrypt_secret(self.lsa_key, v[1])
						
					secret = LSASecret.process(key_name, dec_blob, vl == 'OldVal')
					if secret is not None:
						self.cached_secrets.append(secret)
					
				else:
					logger.debug('[SECURITY] Could not open %s, skipping!' % key_path)
	
	def to_dict(self):
		t = {}
		t['dcc_iteration_count'] = self.dcc_iteration_count
		t['secrets_format'] = 'VISTA' if self.lsa_secret_key_vista_type else 'OLD'
		t['lsa_key'] = self.lsa_key
		t['NK$LM'] = None
		if self.NKLM_key is not None:
			t['NK$LM'] = self.NKLM_key
		t['dcc'] = []
		for secret in self.dcc_hashes:
			t['dcc'].append(secret.to_dict())
		t['cached_secrets'] = []
		for secret in self.cached_secrets:
			t['cached_secrets'].append(secret.to_dict())
		return t
	
	def __str__(self):
		t  = '============== SECURITY hive secrets ==============\r\n'
		t += 'Iteration count: %s\r\n' % self.dcc_iteration_count
		t += 'Secrets structure format : %s\r\n' %  'VISTA' if self.lsa_secret_key_vista_type else 'OLD'
		t += 'LSA Key: %s\r\n' % self.lsa_key.hex()
		if self.NKLM_key is not None:
			t += 'NK$LM Key: %s\r\n' % self.NKLM_key.hex()
		for secret in self.dcc_hashes:
			t += '%s\r\n' % secret.to_lopth()
		for secret in self.cached_secrets:
			t += '%s\r\n' % str(secret)
		return t
