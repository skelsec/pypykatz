#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import json

class SAMSecret:
	def __init__(self, username, rid, nt_hash, lm_hash):
		self.username = username
		self.rid = rid
		self.nt_hash = nt_hash
		self.lm_hash = lm_hash
		
	def to_dict(self):
		return {
			'username' : self.username,
			'rid' : self.rid,
			'nt_hash' : self.nt_hash,
			'lm_hash' : self.lm_hash,
		}
		
	def to_json(self):
		return json.dumps(self.to_dict())
	
	def to_lopth(self):
		return '%s:%s:%s:%s:::' % (self.username, self.rid, self.lm_hash.hex(), self.nt_hash.hex())