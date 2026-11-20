#!/usr/bin/env python3
#
# Author:
#  Matteo Gaeta (@Signum21)
#

from unicrypto.symmetric import AES, MODE_ECB, MODE_GCM
from pypykatz.dpapi.structures.blob import DPAPI_BLOB
from asn1crypto import cms


def aes_key_unwrap(kek, wrapped):
	"""
	RFC 3394 AES Key Unwrap
	"""
	n = len(wrapped) // 8 - 1
	A = wrapped[:8]
	R = [wrapped[8 * (i + 1):8 * (i + 2)] for i in range(n)]
	for j in range(5, -1, -1):
		for i in range(n, 0, -1):
			t = n * j + i
			A_t = (int.from_bytes(A, 'big') ^ t).to_bytes(8, 'big')
			B = AES(kek, mode=MODE_ECB).decrypt(A_t + R[i - 1])
			A = B[:8]
			R[i - 1] = B[8:]
	return b''.join(R)

def der_total_length(data):
	"""
	Returns the total byte length (header + content) of the DER TLV that starts at the beginning of `data`.
    Used to locate the detached content that follows the envelope structure.
	"""
	length_byte = data[1]
	if length_byte & 0x80 == 0:
		return 2 + length_byte
	num_len_bytes = length_byte & 0x7f
	content_length = int.from_bytes(data[2:2 + num_len_bytes], 'big')
	return 2 + num_len_bytes + content_length


class PinnedClipboardItem:
	def __init__(self):
		self.masterkey_guid = None  # GUID string of the masterkey protecting the KEK
		self.kek_blob = None        # DPAPI_BLOB wrapping the KEK
		self.wrapped_cek = None     # AES-key-wrapped content-encryption key
		self.nonce = None           # GCM nonce
		self.tag_length = None      # GCM authentication tag length (bytes)
		self.ciphertext = None      # Detached ciphertext (without the tag)
		self.tag = None             # GCM authentication tag

	@staticmethod
	def from_bytes(data):
		return PinnedClipboardItem.from_buffer(data)

	@staticmethod
	def from_buffer(data):
		item = PinnedClipboardItem()
		ci = cms.ContentInfo.load(data)
		enveloped = ci['content']
		recipient = enveloped['recipient_infos'][0].chosen
		item.kek_blob = DPAPI_BLOB.from_bytes(recipient['kekid']['key_identifier'].native)
		item.masterkey_guid = item.kek_blob.masterkey_guid
		item.wrapped_cek = recipient['encrypted_key'].native
		eci = enveloped['encrypted_content_info']
		alg = eci['content_encryption_algorithm']
		params = alg['parameters'].native
		item.nonce = params['0']
		item.tag_length = params['1']
		detached = data[der_total_length(data):]
		item.ciphertext = detached[:-item.tag_length]
		item.tag = detached[-item.tag_length:]
		return item

	def decrypt(self, masterkey, entropy=None):
		kek = self.kek_blob.decrypt(masterkey, entropy=entropy)
		cek = aes_key_unwrap(kek, self.wrapped_cek)
		cipher = AES(cek, mode=MODE_GCM, IV=self.nonce, segment_size=self.tag_length)
		return cipher.decrypt(self.ciphertext, aad=b'', mac=self.tag)

	def __str__(self):
		t = '== PinnedClipboardItem ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t
