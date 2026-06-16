"""
Tests for MsvDecryptor._autoselect_list_entry (content-based selection of the
LogonSession structure on Win11 25H2, which reports kernel build 26100 and ships
lsass binaries versioned 26100.8655; there the regular PE-timestamp based
selection mispicks KIWI_MSV1_0_LIST_64 instead of the real KIWI_MSV1_0_LIST_65,
producing a garbage Domaine.Buffer (0x140012) and a failing walk).

Run:
    python3 -m unittest tests.test_msv_autoselect -v
or (if pytest is available):
    pytest tests/test_msv_autoselect.py -v

The real-dump tests run only if the dump is available. Its path is taken from
PYPYKATZ_TESTDUMP, defaulting to our repaired Win11 25H2 test minidump (binaries
26100.8655, SystemInfo reports build 26100).
The dump must already be processed by fix_lsass_minidump.py (backfill of the
lsasrv .text pages), otherwise the LSA key is not found - a problem unrelated
to the structure template.
"""
import os
import unittest

from pypykatz.commons.common import KatzSystemArchitecture, WindowsBuild
from pypykatz.lsadecryptor.packages.msv.decryptor import MsvDecryptor
from pypykatz.lsadecryptor.packages.msv.templates import (
    PKIWI_MSV1_0_LIST_64, PKIWI_MSV1_0_LIST_65, KIWI_MSV1_0_LIST_64,
)

TESTDUMP = os.environ.get('PYPYKATZ_TESTDUMP', '/mnt/ssd/lsass-work/test.fixed.dmp')
KNOWN_USER = 'user'
KNOWN_NT = '57d583aa46d571502aad4bb7aea09c70'

SENTINEL = object()  # marker meaning "list_entry was left untouched"


class _Sysinfo:
    def __init__(self, arch, build):
        self.architecture = arch
        self.buildnumber = build


class _Template:
    def __init__(self, list_entry):
        self.list_entry = list_entry


class _StubDecryptor:
    """Minimal stub: in the guard branches _autoselect only reads sysinfo and
    (on exit) decryptor_template.list_entry - no reader/list is needed."""
    def __init__(self, arch, build):
        self.sysinfo = _Sysinfo(arch, build)
        self.decryptor_template = _Template(SENTINEL)
        self.logon_session_count = 1
        self.reader = None

    def log(self, *a, **k):
        raise AssertionError('log() must not be called in guard branches')


class GuardTests(unittest.TestCase):
    """Main regression guard: on non-24H2 and x86 dumps the autoselect must NOT
    activate, so pypykatz behaviour on those builds is unchanged."""

    def _run(self, arch, build):
        stub = _StubDecryptor(arch, build)
        # call the unbound method on the stub
        MsvDecryptor._autoselect_list_entry(stub, entry_ptr_loc=0)
        return stub.decryptor_template.list_entry

    def test_skip_win10_19041(self):
        self.assertIs(self._run(KatzSystemArchitecture.X64, 19041), SENTINEL)

    def test_skip_win7_7601(self):
        self.assertIs(self._run(KatzSystemArchitecture.X64, 7601), SENTINEL)

    def test_skip_build_just_below_24h2(self):
        # boundary: 26099 (< 26100) -> not activated
        self.assertIs(self._run(KatzSystemArchitecture.X64,
                                WindowsBuild.WIN_11_24H2.value - 1), SENTINEL)

    def test_skip_x86_even_on_24h2(self):
        # x86 -> early return even on 24H2
        self.assertIs(self._run(KatzSystemArchitecture.X86,
                                WindowsBuild.WIN_11_24H2.value), SENTINEL)

    # --- Angry: malformed/edge sysinfo must not crash the method ---
    def test_angry_zero_build(self):
        self.assertIs(self._run(KatzSystemArchitecture.X64, 0), SENTINEL)

    def test_angry_huge_build(self):
        # future build > 24H2: the method must try to activate and therefore
        # reach the reader access -> with reader=None that raises -> it must not
        # silently swallow the failure in the guard, nor fail before the guard.
        stub = _StubDecryptor(KatzSystemArchitecture.X64, 99999)
        with self.assertRaises(Exception):
            MsvDecryptor._autoselect_list_entry(stub, entry_ptr_loc=0)


def _build_decryptor(pk):
    from pypykatz.lsadecryptor import MsvTemplate, CredmanTemplate
    dec = MsvDecryptor(
        pk.reader,
        MsvTemplate.get_template(pk.sysinfo),
        pk.lsa_decryptor,
        CredmanTemplate.get_template(pk.sysinfo),
        pk.sysinfo,
    )
    return dec


@unittest.skipUnless(os.path.exists(TESTDUMP), 'no test dump %s' % TESTDUMP)
class RealDumpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from pypykatz.pypykatz import pypykatz
        cls.pk = pypykatz.parse_minidump_file(TESTDUMP)

    def test_default_template_is_list64(self):
        # document the bug itself: the regular selection yields LIST_64 here
        from pypykatz.lsadecryptor import MsvTemplate
        t = MsvTemplate.get_template(self.pk.sysinfo)
        self.assertIs(t.list_entry, PKIWI_MSV1_0_LIST_64,
                      'expected the regular (wrong) LIST_64 for this build')

    def test_autoselect_switches_to_list65(self):
        dec = _build_decryptor(self.pk)
        self.assertIs(dec.decryptor_template.list_entry, PKIWI_MSV1_0_LIST_64)
        _, entry_ptr_loc = dec.find_first_entry()
        dec._autoselect_list_entry(entry_ptr_loc)
        self.assertIs(dec.decryptor_template.list_entry, PKIWI_MSV1_0_LIST_65,
                      'autoselect must switch to LIST_65 on this dump')

    def test_end_to_end_nt_hash(self):
        # full regular path (parse_minidump_file already ran the autoselect)
        found = None
        for ls in self.pk.logon_sessions.values():
            if (ls.username or '').lower() == KNOWN_USER:
                for c in ls.msv_creds:
                    if c.NThash and c.NThash.hex() == KNOWN_NT:
                        found = c
        self.assertIsNotNone(found, 'expected NT hash of user "user" was not recovered')

    def test_angry_without_autoselect_is_broken(self):
        """Angry/control: parsing the first entry with the regular (wrong) LIST_64
        yields a broken Domaine.Buffer (0x140012) and reading the string raises.
        Proves the correct result is delivered by our autoselect, not anything else."""
        dec = _build_decryptor(self.pk)  # default template = LIST_64, autoselect not called
        _, loc = dec.find_first_entry()
        probe = None
        for i in range(dec.logon_session_count):
            dec.reader.move(loc)
            for _ in range(i * 2):
                dec.reader.read_int()
            head = PKIWI_MSV1_0_LIST_64(dec.reader)
            if head.location != head.value:
                probe = head.value
                break
        self.assertIsNotNone(probe, 'could not find a non-empty entry to probe')
        dec.reader.move(probe)
        o = KIWI_MSV1_0_LIST_64(dec.reader)
        with self.assertRaises(Exception):
            o.Domaine.read_string(dec.reader)  # 0x140012 -> not in process memory


if __name__ == '__main__':
    unittest.main(verbosity=2)
