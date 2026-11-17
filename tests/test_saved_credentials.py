"""
Unit tests for --cred-dir offline saved-credential decryption.

No real dump and no plaintext credentials. Uses mocks and synthetic bytes.
"""
import os
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from pypykatz.lsadecryptor.saved_credentials import (
	collect_masterkeys,
	credman_count,
	iter_credential_files,
	blob_to_dict,
	decrypt_credential_directory,
	CRED_DIR_HINT,
)


def mk_cred(guid, masterkey_hex, credtype='dpapi'):
	return SimpleNamespace(
		key_guid=guid,
		masterkey=masterkey_hex,
		credtype=credtype,
	)


# --------------------------------------------------------------------------
# masterkey collection
# --------------------------------------------------------------------------
def test_collect_masterkeys_from_sessions():
	mimi = SimpleNamespace(
		logon_sessions={
			1: SimpleNamespace(dpapi_creds=[mk_cred('g1', 'aabb')], credentials=[]),
			2: SimpleNamespace(dpapi_creds=[mk_cred('g2', 'ccdd')], credentials=[]),
		},
		orphaned_creds=[],
	)
	mk = collect_masterkeys(mimi)
	assert mk == {'g1': bytes.fromhex('aabb'), 'g2': bytes.fromhex('ccdd')}


def test_collect_masterkeys_from_orphaned():
	mimi = SimpleNamespace(
		logon_sessions={},
		orphaned_creds=[mk_cred('g3', 'eeff')],
	)
	assert collect_masterkeys(mimi) == {'g3': bytes.fromhex('eeff')}


def test_collect_masterkeys_skips_bad_hex():
	mimi = SimpleNamespace(
		logon_sessions={1: SimpleNamespace(
			dpapi_creds=[mk_cred('good', 'aabb'), mk_cred('bad', 'NOT_HEX')],
			credentials=[],
		)},
		orphaned_creds=[],
	)
	assert collect_masterkeys(mimi) == {'good': bytes.fromhex('aabb')}


def test_collect_masterkeys_from_session_credentials_list():
	mimi = SimpleNamespace(
		logon_sessions={1: SimpleNamespace(
			dpapi_creds=[],
			credentials=[mk_cred('g4', '1122', credtype='dpapi')],
		)},
		orphaned_creds=[],
	)
	assert collect_masterkeys(mimi) == {'g4': bytes.fromhex('1122')}


# --------------------------------------------------------------------------
# CredMan counting / hint
# --------------------------------------------------------------------------
def test_credman_count_sessions_and_orphans():
	mimi = SimpleNamespace(
		logon_sessions={
			1: SimpleNamespace(credman_creds=[object(), object()]),
			2: SimpleNamespace(credman_creds=[]),
		},
		orphaned_creds=[mk_cred('x', 'aa', credtype='credman')],
	)
	assert credman_count(mimi) == 3


def test_hint_when_credman_zero(monkeypatch, tmp_path):
	# one credential file on disk, no masterkeys, no credman -> hint set
	f = tmp_path / 'AAAA'
	f.write_bytes(b'short garbage')
	mimi = SimpleNamespace(
		logon_sessions={}, orphaned_creds=[],
	)
	res = decrypt_credential_directory(mimi, str(tmp_path))
	assert res['files_seen'] == 1
	assert res['hint'] == CRED_DIR_HINT
	assert '--cred-dir' in res['hint']


def test_no_hint_when_credman_present(monkeypatch, tmp_path):
	mimi = SimpleNamespace(
		logon_sessions={1: SimpleNamespace(credman_creds=[object()])},
		orphaned_creds=[],
	)
	res = decrypt_credential_directory(mimi, str(tmp_path))
	assert res['hint'] is None


# --------------------------------------------------------------------------
# file iteration / blob decoding
# --------------------------------------------------------------------------
def test_iter_credential_files_skips_dirs(tmp_path):
	(tmp_path / 'file1').write_bytes(b'x')
	(tmp_path / 'file2').write_bytes(b'y')
	(tmp_path / 'subdir').mkdir()
	files = list(iter_credential_files(str(tmp_path)))
	assert sorted(os.path.basename(f) for f in files) == ['file1', 'file2']


def test_iter_credential_files_missing_dir():
	assert list(iter_credential_files('/nonexistent/path/xyz')) == []


def test_blob_to_dict_decodes_utf16le():
	blob = SimpleNamespace(
		target='Target'.encode('utf-16-le'),
		target_alias=None,
		description='Desc'.encode('utf-16-le'),
		username='User'.encode('utf-16-le'),
		unknown3='secret'.encode('utf-16-le'),
		type=2,
		type_pretty='generic',
	)
	d = blob_to_dict(blob, '/some/GUID')
	assert d['target'] == 'Target'
	assert d['username'] == 'User'
	assert d['password'] == 'secret'
	assert d['source_file'] == 'GUID'
	assert d['type'] == 2


def test_blob_to_dict_falls_back_to_hex_for_binary():
	blob = SimpleNamespace(
		target=b'\x00\x01\xff',
		target_alias=None,
		description=None,
		username=None,
		unknown3=b'\xde\xad\xbe\xef',
		type=0,
		type_pretty=None,
	)
	d = blob_to_dict(blob, '/x/GUID')
	assert d['target'] == '0001ff' or d['target'] == '0001ff'  # hex fallback
	assert d['password'] == 'deadbeef'


# --------------------------------------------------------------------------
# end-to-end decrypt with a mocked DPAPI
# --------------------------------------------------------------------------
def test_decrypt_directory_bad_file_does_not_abort(monkeypatch, tmp_path):
	import pypykatz.lsadecryptor.saved_credentials as sc

	(tmp_path / 'good').write_bytes(b'GOOD')
	(tmp_path / 'bad').write_bytes(b'BAD')

	class FakeDPAPI:
		def __init__(self):
			self.masterkeys = {}

		def decrypt_credential_bytes(self, data):
			if data == b'BAD':
				raise ValueError('decode failed')
			return SimpleNamespace(
				target=b'target\x00\x00', target_alias=None, description=None,
				username=b'user\x00\x00', unknown3=b'pw\x00\x00',
				type=1, type_pretty='test',
			)

	monkeypatch.setattr(sc, 'DPAPI', FakeDPAPI)
	mimi = SimpleNamespace(
		logon_sessions={1: SimpleNamespace(credman_creds=[object()])},
		orphaned_creds=[],
	)
	res = sc.decrypt_credential_directory(mimi, str(tmp_path))
	assert res['files_seen'] == 2
	assert len(res['credentials']) == 1
	assert len(res['errors']) == 1
	assert res['errors'][0]['file'] == 'bad'
