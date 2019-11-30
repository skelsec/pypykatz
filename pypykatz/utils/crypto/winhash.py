#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import hashlib
from pypykatz.crypto.unified.des import DES, expand_DES_key
from pypykatz.crypto.unified.pbkdf2 import pbkdf2

def LM(password):
	if password is None:
		return bytes.fromhex('aad3b435b51404eeaad3b435b51404ee')
	LM_SECRET = b'KGS!@#$%'
	password_uppercase = password.upper()
	password_uppercase_bytes = password_uppercase.encode('ascii')
	password_uppercase_bytes_padded = password_uppercase_bytes.ljust(14, b'\x00')
	password_chunk_1 = password_uppercase_bytes_padded[0:7]
	password_chunk_2 = password_uppercase_bytes_padded[7:]
	des_chunk_1 = DES(expand_DES_key(password_chunk_1))
	des_chunk_2 = DES(expand_DES_key(password_chunk_2))
	des_first_half = des_chunk_1.encrypt(LM_SECRET)
	des_second_half = des_chunk_2.encrypt(LM_SECRET)
	lm_hash = des_first_half + des_second_half
	
	return lm_hash

def NT(password):
	if password is None:
		return bytes.fromhex('31d6cfe0d16ae931b73c59d7e0c089c0')
	password_bytes = password.encode('utf-16-le')
	md4 = hashlib.new('md4')
	md4.update(password_bytes)
	nt_hash =  md4.digest()	
	return nt_hash
	
def MSDCC(username, password):
	nt_hash_of_password = NT(password)
	username_lower = username.lower()
	username_bytes = username_lower.encode('utf-16-le')
	md4 = hashlib.new('md4')
	md4.update(nt_hash_of_password)
	md4.update(username_bytes)
	dcc =  md4.digest()
	return dcc
	
def MSDCCv2(username, password, iterations = 10240):
	#The iteration count is by default 10240 but it depends on the HKEY_LOCAL_MACHINE\SECURITY\Cache\NL$IterationCount key value.
	msdcc_hash = MSDCC(username, password)
	username_lower = username.lower()
	username_bytes = username_lower.encode('utf-16-le')
	msdcc_v2 = pbkdf2(msdcc_hash, username_bytes, iterations, 16)
	hashcat_format = '$DCC2$%s#%s#%s' % (iterations, username, msdcc_v2.hex())

	return msdcc_v2