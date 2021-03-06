#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
import logging
from pypykatz.crypto.RC4 import RC4
from pypykatz.lsadecryptor.package_commons import PackageDecryptor
from pypykatz.commons.win_datatypes import LONG

class LsaDecryptor_NT5(PackageDecryptor):
	def __init__(self, reader, decryptor_template, sysinfo):
		super().__init__('LsaDecryptor', None, sysinfo, reader)
		self.decryptor_template = decryptor_template
		self.feedback = None
		self.feedback_offset = None
		self.des_key = None
		self.random_key = None
		self.acquire_crypto_material()
		
	def acquire_crypto_material(self):
		self.log('Acquireing crypto stuff...')
		sigpos = self.find_signature()
		self.reader.move(sigpos)
		#data = self.reader.peek(0x50)
		#self.log('Memory looks like this around the signature\n%s' % hexdump(data, start = sigpos))
		
		for x in [self.decryptor_template.feedback_ptr_offset , self.decryptor_template.old_feedback_offset]:
			self.feedback_offset = x

			try:
				self.feedback = self.get_feedback(sigpos)
				#self.log('Feedback bytes:\n%s' % hexdump(self.feedback, start = 0))
				self.des_key = self.get_key(sigpos)
				self.random_key = self.get_random(sigpos)
				#self.log('randomkey bytes:\n%s' % hexdump(self.random_key, start = 0))
			except:
				import traceback
				traceback.print_exc()
				input()
			else:
				break


	def get_feedback(self, sigpos):
		if self.decryptor_template.arch == 'x86':
			new_ptr = self.reader.get_ptr_with_offset(sigpos + self.feedback_offset)
			self.reader.move(new_ptr)
			return self.reader.read(8)
		else:
			self.reader.move(sigpos + self.feedback_offset)
			offset = LONG(self.reader).value
			newpos = sigpos + self.feedback_offset + 4 + offset
			self.reader.move(newpos)
			return self.reader.read(8)

	def get_key(self, sigpos):
		if self.decryptor_template.arch == 'x86':
			new_ptr = self.reader.get_ptr_with_offset(sigpos + self.decryptor_template.desx_key_ptr_offset)
			self.reader.move(new_ptr)
			des_key_ptr = self.decryptor_template.key_struct_ptr(self.reader)
			des_key = des_key_ptr.read(self.reader)
		else:
			self.reader.move(sigpos + self.decryptor_template.desx_key_ptr_offset)
			offset = LONG(self.reader).value
			newpos = sigpos + self.decryptor_template.desx_key_ptr_offset + 4 + offset
			self.reader.move(newpos)
			des_key_ptr = self.decryptor_template.key_struct_ptr(self.reader)
			des_key = des_key_ptr.read(self.reader)

		return des_key
	
	def get_random(self, sigpos):
		if self.decryptor_template.arch == 'x86':
			random_key_ptr = self.reader.get_ptr_with_offset(sigpos + self.decryptor_template.randomkey_ptr_offset)
			random_key_ptr = self.reader.get_ptr_with_offset(random_key_ptr)
			self.reader.move(random_key_ptr)
		else:
			self.reader.move(sigpos + self.decryptor_template.randomkey_ptr_offset)
			offset = LONG(self.reader).value
			newpos = sigpos + self.decryptor_template.desx_key_ptr_offset + 4 + offset
			self.reader.move(newpos)
		
		return self.reader.read(256)

	def find_signature(self):
		self.log('Looking for main struct signature in memory...')
		fl = self.reader.find_in_module('lsasrv.dll', self.decryptor_template.signature)
		if len(fl) == 0:
			logging.debug('signature not found! %s' % self.decryptor_template.signature.hex())
			raise Exception('LSA signature not found!')
			
		self.log('Found candidates on the following positions: %s' % ' '.join(hex(x) for x in fl))
		self.log('Selecting first one @ 0x%08x' % fl[0])
		return fl[0]

	def decrypt(self, encrypted):
		# TODO: NT version specific, move from here in subclasses.
		cleartext = b''
		size = len(encrypted)
		if size:
			if (size % 8) != 0:
				ctx = RC4(self.random_key)
				cleartext = ctx.decrypt(encrypted)
			else:
				#print('Decryption not implemented!')
				cleartext = self.__desx_decrypt(encrypted)
				#raise Exception('Not implemented!')

		return cleartext

	def dump(self):
		self.log('Recovered LSA encryption keys\n')
		self.log('Feedback ({}): {}'.format(len(self.feedback), self.feedback.hex()))
		self.log('Random Key ({}): {}'.format(len(self.random_key), self.random_key.hex()))
		self.log('DESX inputwhitening Key ({}): {}'.format(len(self.des_key.inputWhitening), self.des_key.inputWhitening.hex()))
		self.log('DESX outputwhitening Key ({}): {}'.format(len(self.des_key.outputWhitening), self.des_key.outputWhitening.hex()))
		#self.log('DESX DES Expanded Key ({}): {}' % (self.des_key.desKey.roundKey))

	def __desx_decrypt_internal_block(self, chunk):
		chunk = xor(chunk, self.des_key.outputWhitening)
		chunk = self.__desx_internal_block(chunk, encrypt = False)
		chunk = xor(chunk, self.des_key.inputWhitening)
		return chunk

	def __desx_decrypt(self, data):
		res = b''
		i = 0
		
		IV = self.feedback
		while i != len(data):
			chunk = self.__desx_decrypt_internal_block(data[i:i+8])
			res += xor(chunk, IV)
			IV = data[i:i+8]
			i += 8

		return res

	def __desx_internal_block(self, data, encrypt = False):
		L = int.from_bytes(data[4:], 'little', signed = False)
		R = int.from_bytes(data[:4], 'little', signed = False)
		
		#t = 'ORIGINAL L: %s R: %s' % (L,R)
		#input(t)

		#print(hex(R))
		R = rol32(R, 4)
		#input(hex(R))
		Ta = (L ^ R) & 0xf0f0f0f0
		#input('Ta ' + hex(Ta))
		L = L ^ Ta
		R = R ^ Ta
		L = rol32(L, 20)
		Ta = (L ^ R) & 0xfff0000f
		#input('Ta ' + hex(Ta))
		L = L ^ Ta
		R = R ^ Ta
		L = rol32(L, 14)
		Ta = (L ^ R) & 0x33333333
		#input('Ta ' + hex(Ta))
		L = L ^ Ta
		R = R ^ Ta
		R = rol32(R, 22)
		Ta = (L ^ R) & 0x03fc03fc
		#input('Ta ' + hex(Ta))
		L = L ^ Ta
		R = R ^ Ta
		R = rol32(R, 9)
		Ta = (L ^ R) & 0xaaaaaaaa
		#input('Ta ' + hex(Ta))
		L = L ^ Ta
		R = R ^ Ta
		L = rol32(L, 1)

		#t = 'BEFORE F! L: %s R: %s' % (L,R)
		#input(t)

		if encrypt:
			for i in range(0,14, 2):
				L, R = F(L, R, self.des_key.desKey.roundKey[i])
				R, L = F(R, L, self.des_key.desKey.roundKey[i +1])

		else:
			for i in range(14, -2, -2):
				#print(i)
				L, R = F(L, R, self.des_key.desKey.roundKey[i + 1])
				#t = 'F(%s) L: %s R: %s' % (i, L,R)
				#input(t)
				R, L = F(R, L, self.des_key.desKey.roundKey[i])
				#t = 'F(%s) L: %s R: %s' % (i, L,R)
				#input(t)
		
		#t = 'AFTER F! L: %s R: %s' % (L,R)
		#input(t)

		R = ror32(R, 1)
		Ta = (L ^ R) & 0xaaaaaaaa
		L = L ^ Ta
		R = R ^ Ta
		L = ror32(L, 9)
		Ta = (L ^ R) & 0x03fc03fc
		L ^= Ta
		R ^= Ta
		L = ror32(L, 22)
		Ta = (L ^ R) & 0x33333333
		L ^= Ta
		R ^= Ta
		R = ror32(R, 14)
		Ta = (L ^ R) & 0xfff0000f
		L ^= Ta
		R ^= Ta
		R = ror32(R, 20)
		Ta = (L ^ R) & 0xf0f0f0f0
		L ^= Ta
		R ^= Ta
		L = ror32(L, 4)

		return L.to_bytes(4, 'little', signed = False) + R.to_bytes(4, 'little', signed = False)


SymCryptDesSpbox = [
	[
	0x02080800, 0x00080000, 0x02000002, 0x02080802, 0x02000000, 0x00080802, 0x00080002, 0x02000002, 0x00080802, 0x02080800, 0x02080000, 0x00000802, 0x02000802, 0x02000000, 0x00000000, 0x00080002,
	0x00080000, 0x00000002, 0x02000800, 0x00080800, 0x02080802, 0x02080000, 0x00000802, 0x02000800, 0x00000002, 0x00000800, 0x00080800, 0x02080002, 0x00000800, 0x02000802, 0x02080002, 0x00000000,
	0x00000000, 0x02080802, 0x02000800, 0x00080002, 0x02080800, 0x00080000, 0x00000802, 0x02000800, 0x02080002, 0x00000800, 0x00080800, 0x02000002, 0x00080802, 0x00000002, 0x02000002, 0x02080000,
	0x02080802, 0x00080800, 0x02080000, 0x02000802, 0x02000000, 0x00000802, 0x00080002, 0x00000000, 0x00080000, 0x02000000, 0x02000802, 0x02080800, 0x00000002, 0x02080002, 0x00000800, 0x00080802,
	],
	[
	0x40108010, 0x00000000, 0x00108000, 0x40100000, 0x40000010, 0x00008010, 0x40008000, 0x00108000, 0x00008000, 0x40100010, 0x00000010, 0x40008000, 0x00100010, 0x40108000, 0x40100000, 0x00000010,
	0x00100000, 0x40008010, 0x40100010, 0x00008000, 0x00108010, 0x40000000, 0x00000000, 0x00100010, 0x40008010, 0x00108010, 0x40108000, 0x40000010, 0x40000000, 0x00100000, 0x00008010, 0x40108010,
	0x00100010, 0x40108000, 0x40008000, 0x00108010, 0x40108010, 0x00100010, 0x40000010, 0x00000000, 0x40000000, 0x00008010, 0x00100000, 0x40100010, 0x00008000, 0x40000000, 0x00108010, 0x40008010,
	0x40108000, 0x00008000, 0x00000000, 0x40000010, 0x00000010, 0x40108010, 0x00108000, 0x40100000, 0x40100010, 0x00100000, 0x00008010, 0x40008000, 0x40008010, 0x00000010, 0x40100000, 0x00108000,
	],
	[
	0x04000001, 0x04040100, 0x00000100, 0x04000101, 0x00040001, 0x04000000, 0x04000101, 0x00040100, 0x04000100, 0x00040000, 0x04040000, 0x00000001, 0x04040101, 0x00000101, 0x00000001, 0x04040001,
	0x00000000, 0x00040001, 0x04040100, 0x00000100, 0x00000101, 0x04040101, 0x00040000, 0x04000001, 0x04040001, 0x04000100, 0x00040101, 0x04040000, 0x00040100, 0x00000000, 0x04000000, 0x00040101,
	0x04040100, 0x00000100, 0x00000001, 0x00040000, 0x00000101, 0x00040001, 0x04040000, 0x04000101, 0x00000000, 0x04040100, 0x00040100, 0x04040001, 0x00040001, 0x04000000, 0x04040101, 0x00000001,
	0x00040101, 0x04000001, 0x04000000, 0x04040101, 0x00040000, 0x04000100, 0x04000101, 0x00040100, 0x04000100, 0x00000000, 0x04040001, 0x00000101, 0x04000001, 0x00040101, 0x00000100, 0x04040000,
	],
	[
	0x00401008, 0x10001000, 0x00000008, 0x10401008, 0x00000000, 0x10400000, 0x10001008, 0x00400008, 0x10401000, 0x10000008, 0x10000000, 0x00001008, 0x10000008, 0x00401008, 0x00400000, 0x10000000,
	0x10400008, 0x00401000, 0x00001000, 0x00000008, 0x00401000, 0x10001008, 0x10400000, 0x00001000, 0x00001008, 0x00000000, 0x00400008, 0x10401000, 0x10001000, 0x10400008, 0x10401008, 0x00400000,
	0x10400008, 0x00001008, 0x00400000, 0x10000008, 0x00401000, 0x10001000, 0x00000008, 0x10400000, 0x10001008, 0x00000000, 0x00001000, 0x00400008, 0x00000000, 0x10400008, 0x10401000, 0x00001000,
	0x10000000, 0x10401008, 0x00401008, 0x00400000, 0x10401008, 0x00000008, 0x10001000, 0x00401008, 0x00400008, 0x00401000, 0x10400000, 0x10001008, 0x00001008, 0x10000000, 0x10000008, 0x10401000,
	],
	[
	0x08000000, 0x00010000, 0x00000400, 0x08010420, 0x08010020, 0x08000400, 0x00010420, 0x08010000, 0x00010000, 0x00000020, 0x08000020, 0x00010400, 0x08000420, 0x08010020, 0x08010400, 0x00000000,
	0x00010400, 0x08000000, 0x00010020, 0x00000420, 0x08000400, 0x00010420, 0x00000000, 0x08000020, 0x00000020, 0x08000420, 0x08010420, 0x00010020, 0x08010000, 0x00000400, 0x00000420, 0x08010400,
	0x08010400, 0x08000420, 0x00010020, 0x08010000, 0x00010000, 0x00000020, 0x08000020, 0x08000400, 0x08000000, 0x00010400, 0x08010420, 0x00000000, 0x00010420, 0x08000000, 0x00000400, 0x00010020,
	0x08000420, 0x00000400, 0x00000000, 0x08010420, 0x08010020, 0x08010400, 0x00000420, 0x00010000, 0x00010400, 0x08010020, 0x08000400, 0x00000420, 0x00000020, 0x00010420, 0x08010000, 0x08000020,
	],
	[
	0x80000040, 0x00200040, 0x00000000, 0x80202000, 0x00200040, 0x00002000, 0x80002040, 0x00200000, 0x00002040, 0x80202040, 0x00202000, 0x80000000, 0x80002000, 0x80000040, 0x80200000, 0x00202040,
	0x00200000, 0x80002040, 0x80200040, 0x00000000, 0x00002000, 0x00000040, 0x80202000, 0x80200040, 0x80202040, 0x80200000, 0x80000000, 0x00002040, 0x00000040, 0x00202000, 0x00202040, 0x80002000,
	0x00002040, 0x80000000, 0x80002000, 0x00202040, 0x80202000, 0x00200040, 0x00000000, 0x80002000, 0x80000000, 0x00002000, 0x80200040, 0x00200000, 0x00200040, 0x80202040, 0x00202000, 0x00000040,
	0x80202040, 0x00202000, 0x00200000, 0x80002040, 0x80000040, 0x80200000, 0x00202040, 0x00000000, 0x00002000, 0x80000040, 0x80002040, 0x80202000, 0x80200000, 0x00002040, 0x00000040, 0x80200040,
	],
	[
	0x00004000, 0x00000200, 0x01000200, 0x01000004, 0x01004204, 0x00004004, 0x00004200, 0x00000000, 0x01000000, 0x01000204, 0x00000204, 0x01004000, 0x00000004, 0x01004200, 0x01004000, 0x00000204,
	0x01000204, 0x00004000, 0x00004004, 0x01004204, 0x00000000, 0x01000200, 0x01000004, 0x00004200, 0x01004004, 0x00004204, 0x01004200, 0x00000004, 0x00004204, 0x01004004, 0x00000200, 0x01000000,
	0x00004204, 0x01004000, 0x01004004, 0x00000204, 0x00004000, 0x00000200, 0x01000000, 0x01004004, 0x01000204, 0x00004204, 0x00004200, 0x00000000, 0x00000200, 0x01000004, 0x00000004, 0x01000200,
	0x00000000, 0x01000204, 0x01000200, 0x00004200, 0x00000204, 0x00004000, 0x01004204, 0x01000000, 0x01004200, 0x00000004, 0x00004004, 0x01004204, 0x01000004, 0x01004200, 0x01004000, 0x00004004,
	],
	[
	0x20800080, 0x20820000, 0x00020080, 0x00000000, 0x20020000, 0x00800080, 0x20800000, 0x20820080, 0x00000080, 0x20000000, 0x00820000, 0x00020080, 0x00820080, 0x20020080, 0x20000080, 0x20800000,
	0x00020000, 0x00820080, 0x00800080, 0x20020000, 0x20820080, 0x20000080, 0x00000000, 0x00820000, 0x20000000, 0x00800000, 0x20020080, 0x20800080, 0x00800000, 0x00020000, 0x20820000, 0x00000080,
	0x00800000, 0x00020000, 0x20000080, 0x20820080, 0x00020080, 0x20000000, 0x00000000, 0x00820000, 0x20800080, 0x20020080, 0x20020000, 0x00800080, 0x20820000, 0x00000080, 0x00800080, 0x20020000,
	0x20820080, 0x00800000, 0x20800000, 0x20000080, 0x00820000, 0x00020080, 0x20020080, 0x20800000, 0x00000080, 0x20820000, 0x00820080, 0x00000000, 0x20000000, 0x20800080, 0x00020000, 0x00820080,
	],
]

def F(L, R, keya):
	Ta = keya[0] ^ R
	Tb = keya[1] ^ R
	Tb = ror32(Tb, 4)
	L ^= SymCryptDesSpbox[0][ (Ta     & 0xfc) // 4]
	L ^= SymCryptDesSpbox[1][ (Tb     & 0xfc) // 4]
	L ^= SymCryptDesSpbox[2][((Ta>> 8)& 0xfc)//4]
	L ^= SymCryptDesSpbox[3][((Tb>> 8)& 0xfc)//4]
	L ^= SymCryptDesSpbox[4][((Ta>>16)& 0xfc)//4]
	L ^= SymCryptDesSpbox[5][((Tb>>16)& 0xfc)//4]
	L ^= SymCryptDesSpbox[6][((Ta>>24)& 0xfc)//4]
	L ^= SymCryptDesSpbox[7][((Tb>>24)& 0xfc)//4]
	return L, R


def rol32(n, d):
	return ((n << d)|(n >> (32 - d))) & 0xFFFFFFFF

def ror32(n, d):
	return ((n >> d)|(n << (32 - d))) & 0xFFFFFFFF

def xor(d1, d2):
	return bytes(a ^ b for (a, b) in zip(d1, d2))

