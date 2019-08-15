
import base64
from pypykatz.crypto.unified.aes import AES
from pypykatz.crypto.unified.common import SYMMETRIC_MODE
from pypykatz.crypto.unified.pkcs7 import unpad as pkcs7_unpad


def gppassword(pw_enc_b64):
	AES_KEY = b'\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b'
	AES_IV = b'\x00'*16
		
	pad = len(pw_enc_b64) % 4
	if pad == 1:
		pw_enc_b64 = pw_enc_b64[:-1]
	elif pad == 2 or pad == 3:
		pw_enc_b64 += '=' * (4 - pad)
		
	pw_enc = base64.b64decode(pw_enc_b64)
	
	ctx = AES(AES_KEY, mode = SYMMETRIC_MODE.CBC, iv = AES_IV)
	pw_dec  = pkcs7_unpad(ctx.decrypt(pw_enc))
	
	return pw_dec.decode('utf-16-le')
	