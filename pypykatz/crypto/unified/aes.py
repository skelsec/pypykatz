from pypykatz.crypto.aes import AESModeOfOperationCBC, AESModeOfOperationECB
from pypykatz.crypto.unified.common import SYMMETRIC_MODE
	

class AES:
	def __init__(self, key, mode = SYMMETRIC_MODE.ECB, iv = None):
		self.key = key
		self.mode = mode
		self.iv = iv
		self.block_size = len(key)
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
		return self.ctx.encrypt(data)
	
	def decrypt(self, data):
		return self.ctx.decrypt(data)