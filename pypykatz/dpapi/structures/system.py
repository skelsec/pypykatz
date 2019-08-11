#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import io
import enum


class DPAPI_SYSTEM:
	def __init__(self):
		self.version = None
		self.machine_key = None
		self.user_key = None
	
	@staticmethod
	def from_bytes(data):
		return DPAPI_SYSTEM.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		sk = DPAPI_SYSTEM()
		sk.version = int.from_bytes(buff.read(4), 'little', signed = False) 
		sk.machine_key = buff.read(20)
		sk.user_key = buff.read(20)
		return sk
		
	def __str__(self):
		t = '== DPAPI_SYSTEM ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t