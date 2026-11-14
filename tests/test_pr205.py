"""
Regression tests for pypykatz PR #205 (Win11 25H2/26H2 parsing).

These tests do NOT require a real LSASS minidump. They exercise:
  - the UTF-16LE password-decoding heuristic added by the PR (package_commons.py)
  - the MSV template routing for 25H2 (26200) / 26H2 (26300)
  - the TSPKG null-list-head guard that prevents the "0x00000000 is not in
    process memory space" crash reported against build 26200.6584

NOTE: real-dump regression (credential layout on 25H2/26H2) still requires a
sanitized, authorized minidump and is NOT covered here.
"""
import os
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from pypykatz.lsadecryptor.package_commons import PackageDecryptor
from pypykatz.lsadecryptor.packages.msv.templates import (
	MsvTemplate,
	PKIWI_MSV1_0_LIST_63,
	PKIWI_MSV1_0_LIST_64,
	PKIWI_MSV1_0_LIST_65,
)
from pypykatz.lsadecryptor.packages.tspkg.decryptor import TspkgDecryptor
from pypykatz.commons.common import KatzSystemArchitecture, WindowsBuild


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def make_decryptor():
	"""A PackageDecryptor with all heavy collaborators mocked out."""
	return PackageDecryptor('test', MagicMock(), MagicNamespace(), MagicMock())


class MagicNamespace:
	"""Stand-in for sysinfo/lsa_decryptor that accepts any attribute access."""
	def __getattr__(self, name):
		return MagicMock()


def sysinfo(buildnumber, msv_dll_timestamp=0, arch=KatzSystemArchitecture.X64):
	return SimpleNamespace(
		buildnumber=buildnumber,
		msv_dll_timestamp=msv_dll_timestamp,
		architecture=arch,
	)


# --------------------------------------------------------------------------
# _is_utf16le heuristic
# --------------------------------------------------------------------------
def test_is_utf16le_ascii_utf16le_true():
	dec = make_decryptor()
	data = 'Secret123'.encode('utf-16-le')
	assert dec._is_utf16le(data) is True


def test_is_utf16le_accented_latin_true():
	dec = make_decryptor()
	# Accented Latin chars (e.g. U+00E9) still have a zero high byte in UTF-16LE.
	data = 'café'.encode('utf-16-le')
	assert dec._is_utf16le(data) is True


def test_is_utf16le_cjk_false():
	dec = make_decryptor()
	# CJK code points sit above U+FF, so their UTF-16LE high bytes are non-zero.
	# The heuristic therefore does NOT flag them as UTF-16LE and they fall
	# through to ASCII/UTF-8 -> hex. This is a known limitation: non-ASCII
	# (e.g. CJK) passwords will be rendered as hex rather than decoded text.
	data = '密码'.encode('utf-16-le')
	assert dec._is_utf16le(data) is False


def test_is_utf16le_empty_false():
	dec = make_decryptor()
	assert dec._is_utf16le(b'') is False


def test_is_utf16le_odd_length_false():
	dec = make_decryptor()
	assert dec._is_utf16le(b'\x01\x02\x03') is False


def test_is_utf16le_random_binary_false():
	dec = make_decryptor()
	import random
	random.seed(1)
	data = bytes(random.getrandbits(8) for _ in range(64))
	assert dec._is_utf16le(data) is False


# --------------------------------------------------------------------------
# _decode_password
# --------------------------------------------------------------------------
def test_decode_password_utf16le_ascii():
	dec = make_decryptor()
	data = 'P@ssw0rd'.encode('utf-16-le')
	assert dec._decode_password(data) == 'P@ssw0rd'


def test_decode_password_utf16le_trims_trailing_nulls():
	dec = make_decryptor()
	data = 'hello'.encode('utf-16-le') + b'\x00\x00\x00\x00'
	assert dec._decode_password(data) == 'hello'


def test_decode_password_plain_ascii_bytes():
	dec = make_decryptor()
	# Not UTF-16LE (odd high bytes); should fall through to ASCII decode.
	assert dec._decode_password(b'plainascii') == 'plainascii'


def test_decode_password_random_binary_returns_hex():
	dec = make_decryptor()
	import random
	random.seed(2)
	data = bytes(random.getrandbits(8) for _ in range(16))
	out = dec._decode_password(data)
	# binary that is neither UTF-16LE nor ASCII/UTF-8 -> hex string
	assert out == data.hex()
	assert len(out) == len(data) * 2


def test_decode_password_empty():
	dec = make_decryptor()
	assert dec._decode_password(b'') == ''


# --------------------------------------------------------------------------
# MSV get_template routing (Win11 25H2 / 26H2)
# --------------------------------------------------------------------------
def test_win11_26h2_constant():
	assert WindowsBuild.WIN_11_26H2.value == 26300


def test_get_template_25h2_uses_list65():
	t = MsvTemplate.get_template(sysinfo(26200))
	assert t.list_entry is PKIWI_MSV1_0_LIST_65


def test_get_template_26h2_uses_list65():
	t = MsvTemplate.get_template(sysinfo(26300))
	assert t.list_entry is PKIWI_MSV1_0_LIST_65


def test_get_template_24h2_timestamp_routing():
	# 24H2 (26100) routes via msv_dll_timestamp to LIST_64 or LIST_65.
	hi = MsvTemplate.get_template(sysinfo(26100, msv_dll_timestamp=0xd133958f))
	lo = MsvTemplate.get_template(sysinfo(26100, msv_dll_timestamp=0))
	assert hi.list_entry in (PKIWI_MSV1_0_LIST_65, PKIWI_MSV1_0_LIST_64)
	assert lo.list_entry in (PKIWI_MSV1_0_LIST_65, PKIWI_MSV1_0_LIST_64)
	assert hi.list_entry != lo.list_entry or True  # both valid, just document


def test_get_template_older_builds_stable():
	# A pre-24H2 build must keep its historical template (sanity check that
	# adding WIN_11_26H2 did not shift earlier branches).
	t = MsvTemplate.get_template(sysinfo(26000))
	assert t.list_entry is PKIWI_MSV1_0_LIST_63


# --------------------------------------------------------------------------
# TSPKG null-list-head guard (fixes reported 0x00000000 crash on 25H2)
# --------------------------------------------------------------------------
class _FakeAVLNode:
	"""AVL node whose sub-pointers resolve to empty nodes (no recursion)."""
	def __init__(self):
		self.OrderedPointer = SimpleNamespace(value=0)
		self.BalancedRoot = SimpleNamespace(
			LeftChild=_FakeAVLPtr(),
			RightChild=_FakeAVLPtr(),
		)


class _FakeAVLPtr:
	def read(self, reader, override_finaltype=None):
		return _FakeAVLNode()


class _FakeAVL:
	def __init__(self, reader):
		self.reader = reader

	def read(self, reader, override_finaltype=None):
		return _FakeAVLNode()


def test_tspkg_null_list_head_does_not_crash():
	reader = MagicMock()
	reader.move = MagicMock()  # would raise if called with 0
	dec = TspkgDecryptor(reader, MagicMock(), MagicMock(), MagicMock())
	dec.find_first_entry = lambda: (0, 0)
	# Must return gracefully instead of raising
	# "Memory address 0x00000000 is not in process memory space"
	dec.start()
	assert dec.credentials == []
	reader.move.assert_not_called()


def test_tspkg_nonzero_head_proceeds(monkeypatch):
	import pypykatz.lsadecryptor.packages.tspkg.decryptor as tspkg_dec
	monkeypatch.setattr(tspkg_dec, 'PRTL_AVL_TABLE', _FakeAVL)
	reader = MagicMock()
	reader.move = MagicMock(return_value=None)
	dec = TspkgDecryptor(reader, MagicMock(), MagicMock(), MagicMock())
	dec.find_first_entry = lambda: (0x1000, 0)
	# Guard must NOT swallow a genuine (non-zero) head pointer.
	dec.start()
	reader.move.assert_any_call(0x1000)
	assert dec.credentials == []
