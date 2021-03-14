#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
from pypykatz.alsadecryptor.lsa_template_nt5 import LsaTemplate_NT5
from pypykatz.alsadecryptor.lsa_template_nt6 import LsaTemplate_NT6
from pypykatz.alsadecryptor.lsa_decryptor_nt6 import LsaDecryptor_NT6
from pypykatz.alsadecryptor.lsa_decryptor_nt5 import LsaDecryptor_NT5

class LsaDecryptor:
	def __init__(self):
		pass
	
	@staticmethod
	def choose(reader, decryptor_template, sysinfo):
		if isinstance(decryptor_template, LsaTemplate_NT5):
			return LsaDecryptor_NT5(reader, decryptor_template, sysinfo)
		else:
			return LsaDecryptor_NT6(reader, decryptor_template, sysinfo)