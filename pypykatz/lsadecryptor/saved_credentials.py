"""
Offline decryption of Windows saved credentials (Credential Manager / DPAPI
credential files) using masterkeys recovered from an LSASS minidump.

Rationale
---------
A minidump only contains process memory, not the on-disk credential files
under %LOCALAPPDATA%\\Microsoft\\Credentials. The MSV `credman` package parses
the in-memory CredentialManager lists, but those lists may be missing or
malformed in a given dump (e.g. produced by memprocfs conversion). The
persisted credential files, copied from the target to the analyst machine,
carry the same secrets and can be decrypted with the DPAPI masterkeys that
*are* present in the dump (MSV `dpapi_creds`).

This module glues together two existing pypykatz primitives:
  - DPAPI masterkeys from the already-parsed result object (no second parse)
  - DPAPI.decrypt_credential_bytes() for each credential file

Nothing here changes how the dump itself is parsed.
"""
import os
import glob

from pypykatz import logger
from pypykatz.dpapi.dpapi import DPAPI


CRED_DIR_HINT = (
	"No CredMan credentials were parsed from the dump. The dump may not "
	"contain the in-memory CredentialManager lists. Copy the credential "
	"files from the target (%LOCALAPPDATA%\\Microsoft\\Credentials and "
	"%APPDATA%\\Microsoft\\Credentials) to a local directory and re-run with "
	"--cred-dir <directory> to decrypt saved credentials offline."
)


def collect_masterkeys(mimi):
	"""Collect guid -> keybytes from an already-parsed pypykatz result object.

	Reads both per-session dpapi_creds and orphaned dpapi creds. Never
	re-parses the dump, so the walk_list fault tolerance in package_commons
	already applies and a malformed CredMan entry cannot abort this.
	"""
	masterkeys = {}

	def add_from(cred):
		guid = getattr(cred, 'key_guid', None)
		mk = getattr(cred, 'masterkey', None)
		if not guid or not mk:
			return
		try:
			masterkeys[guid] = bytes.fromhex(mk)
		except (ValueError, TypeError):
			pass

	for session in getattr(mimi, 'logon_sessions', {}).values():
		for cred in getattr(session, 'dpapi_creds', []) or []:
			add_from(cred)
		# Some builds place DPAPI keys in the session's generic cred list.
		for cred in getattr(session, 'credentials', []) or []:
			if getattr(cred, 'credtype', None) == 'dpapi':
				add_from(cred)

	for cred in getattr(mimi, 'orphaned_creds', []) or []:
		if getattr(cred, 'credtype', None) == 'dpapi' or hasattr(cred, 'masterkey'):
			add_from(cred)

	return masterkeys


def credman_count(mimi):
	"""Total number of CredMan credentials across sessions and orphans."""
	n = 0
	for session in getattr(mimi, 'logon_sessions', {}).values():
		n += len(getattr(session, 'credman_creds', []) or [])
	for cred in getattr(mimi, 'orphaned_creds', []) or []:
		if getattr(cred, 'credtype', None) == 'credman':
			n += 1
	return n


def iter_credential_files(cred_dir):
	"""Yield file paths directly under cred_dir that look like credential files.

	Windows credential files are flat files named by an uppercase GUID hex.
	We accept all regular files (non-recursive) and let the DPAPI parser decide;
	oversized files are skipped to keep the operation bounded.
	"""
	if not cred_dir or not os.path.isdir(cred_dir):
		return
	for path in sorted(glob.glob(os.path.join(cred_dir, '*'))):
		if not os.path.isfile(path):
			continue
		try:
			if os.path.getsize(path) > 2 * 1024 * 1024:
				continue
		except OSError:
			continue
		yield path


def blob_to_dict(blob, source_path):
	"""Turn a CREDENTIAL_BLOB into a JSON-safe dict (no raw bytes)."""
	def dec(value):
		if value is None:
			return None
		if isinstance(value, bytes):
			# Credential payloads are UTF-16LE; fall back to hex if not decodable.
			try:
				s = value.decode('utf-16-le').rstrip('\x00')
				if s and all(ch.isprintable() or ch in '\r\n\t' for ch in s):
					return s
			except (UnicodeDecodeError, AttributeError):
				pass
			return value.hex()
		return value

	return {
		'source_file': os.path.basename(source_path),
		'target': dec(getattr(blob, 'target', None)),
		'target_alias': dec(getattr(blob, 'target_alias', None)),
		'description': dec(getattr(blob, 'description', None)),
		'username': dec(getattr(blob, 'username', None)),
		'password': dec(getattr(blob, 'unknown3', None)),
		'type': getattr(blob, 'type', None),
		'type_pretty': getattr(blob, 'type_pretty', None),
	}


def decrypt_credential_directory(mimi, cred_dir):
	"""Decrypt all credential files in cred_dir with masterkeys from mimi.

	Returns a dict with 'credentials', 'errors', 'files_seen', 'hint' suitable
	for attaching to the result object / JSON output.
	"""
	result = {
		'credentials': [],
		'errors': [],
		'files_seen': 0,
		'hint': None,
	}
	masterkeys = collect_masterkeys(mimi)
	logger.info('[cred-dir] recovered %d DPAPI masterkeys from dump' % len(masterkeys))

	paths = list(iter_credential_files(cred_dir))
	result['files_seen'] = len(paths)

	dpapi = DPAPI()
	dpapi.masterkeys = masterkeys

	for path in paths:
		try:
			with open(path, 'rb') as f:
				data = f.read()
			blob = dpapi.decrypt_credential_bytes(data)
			result['credentials'].append(blob_to_dict(blob, path))
		except Exception as e:
			result['errors'].append({
				'file': os.path.basename(path),
				'error': '%s: %s' % (type(e).__name__, e),
			})

	if credman_count(mimi) == 0:
		result['hint'] = CRED_DIR_HINT

	return result
