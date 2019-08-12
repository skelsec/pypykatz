
import base64
from pypykatz.crypto.unified.aes import AES
from pypykatz.crypto.unified.common import SYMMETRIC_MODE

AES_KEY = b'\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b'
AES_IV = b'\x00'*16

class GPPassword:
	def __init__(self):
		pass
		
	def decrypt(self, data):
		
		pad = len(data) % 4
		if pad == 1:
			data = data[:-1]
		elif pad == 2 or pad == 3:
			data += '=' * (4 - pad)
			
		pw_enc = base64.b64decode(data)
		
		ctx = AES(AES_KEY, iv = AES_IV)
		pw_dec  = ctx.decrypt(pw_enc)
		
		return pw_dec.decode('utf-16-le')
	