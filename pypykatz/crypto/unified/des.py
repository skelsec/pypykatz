#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from pypykatz.crypto.des import des, ECB, CBC, expand_DES_key
from pypykatz.crypto.unified.common import SYMMETRIC_MODE
	

class DES:
	def __init__(self, key, mode = SYMMETRIC_MODE.ECB, iv = None):
		self.key = key
		self.mode = mode
		self.iv = iv
		self.block_size = 8
		self.ctx = None
		self.setup()
		
	def setup(self):
		if len(self.key) == 7:
			self.key = expand_DES_key(self.key)
			
		if self.mode == SYMMETRIC_MODE.ECB:
			self.ctx = des(self.key, mode = ECB)
		elif self.mode == SYMMETRIC_MODE.CBC:
			self.ctx = des(self.key, mode = CBC, IV = self.iv)
		else:
			raise Exception('Unknown mode!')
		
	def encrypt(self, data):
		return self.ctx.encrypt(data)
	
	def decrypt(self, data):
		return self.ctx.decrypt(data)