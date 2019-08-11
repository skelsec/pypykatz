#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from pypykatz.crypto.aes import AESModeOfOperationCBC, AESModeOfOperationECB
from pypykatz.crypto.unified.common import SYMMETRIC_MODE
	

class AES:
	def __init__(self, key, mode = SYMMETRIC_MODE.ECB, iv = None):
		self.key = key
		self.mode = mode
		self.iv = iv
		self.block_size = 16
		self.ctx = None
		self.setup()
		
	def setup(self):
		if self.mode == SYMMETRIC_MODE.ECB:
			self.ctx = AESModeOfOperationECB(self.key)
		elif self.mode == SYMMETRIC_MODE.CBC:
			self.ctx = AESModeOfOperationCBC(self.key, iv = self.iv)
		else:
			raise Exception('Unknown mode!')
		
	def encrypt(self, data):
		if len(data) % self.block_size != 0:
			raise Exception('Data size not matching blocksize!')
		res = b''
		for block in [data[i:i+self.block_size] for i in range(0, len(data), self.block_size)]:  #terrible, terrible workaround
			res += self.ctx.encrypt(block)
		return res
	
	def decrypt(self, data):
		if len(data) % self.block_size != 0:
			raise Exception('Data size not matching blocksize!')
		res = b''
		for block in [data[i:i+self.block_size] for i in range(0, len(data), self.block_size)]:  #terrible, terrible workaround
			res += self.ctx.decrypt(block)
		return res