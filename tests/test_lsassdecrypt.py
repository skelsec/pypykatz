import os
import json
from pypykatz.pypykatz import pypykatz
from .config import TESTFILES_DIR, compare_jsons


def test_x64_win7_7601():
    basedir = os.path.join(TESTFILES_DIR, 'x64', 'win7')
    with open(os.path.join(basedir, '7601.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '7601.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x64_win7_7601_1():
    basedir = os.path.join(TESTFILES_DIR, 'x64', 'win7')
    with open(os.path.join(basedir, '7601_1.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '7601_1.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x64_win10_10240():
    basedir = os.path.join(TESTFILES_DIR, 'x64', 'win10')
    with open(os.path.join(basedir, '10240.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '10240.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x64_win10_10240_2():
    basedir = os.path.join(TESTFILES_DIR, 'x64', 'win10')
    with open(os.path.join(basedir, '10240_2.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '10240_2.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x64_win10_10240_3():
    basedir = os.path.join(TESTFILES_DIR, 'x64', 'win10')
    with open(os.path.join(basedir, '10240_3.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '10240_3.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x64_win10_10240_4():
    basedir = os.path.join(TESTFILES_DIR, 'x64', 'win10')
    with open(os.path.join(basedir, '10240_4.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '10240_4.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x64_win10_15063():
    basedir = os.path.join(TESTFILES_DIR, 'x64', 'win10')
    with open(os.path.join(basedir, '15063.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '15063.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x64_win10_16299():
    basedir = os.path.join(TESTFILES_DIR, 'x64', 'win10')
    with open(os.path.join(basedir, '16299.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '16299.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x64_win10_18362():
    basedir = os.path.join(TESTFILES_DIR, 'x64', 'win10')
    with open(os.path.join(basedir, '18362.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '18362.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x64_win10_19041():
    basedir = os.path.join(TESTFILES_DIR, 'x64', 'win10')
    with open(os.path.join(basedir, '19041.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '19041.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x64_win10_19044():
    basedir = os.path.join(TESTFILES_DIR, 'x64', 'win10')
    with open(os.path.join(basedir, '19044.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '19044.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x64_win81_9600():
    basedir = os.path.join(TESTFILES_DIR, 'x64', 'win81')
    with open(os.path.join(basedir, '9600.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '9600.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x64_win81_9600_1():
    basedir = os.path.join(TESTFILES_DIR, 'x64', 'win81')
    with open(os.path.join(basedir, '9600_1.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '9600_1.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x64_win2008R2_7601():
    basedir = os.path.join(TESTFILES_DIR, 'x64', 'win2008R2')
    with open(os.path.join(basedir, '7601.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '7601.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x64_win2012_9600():
    basedir = os.path.join(TESTFILES_DIR, 'x64', 'win2012')
    with open(os.path.join(basedir, '9600.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '9600.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x64_win2016_14393():
    basedir = os.path.join(TESTFILES_DIR, 'x64', 'win2016')
    with open(os.path.join(basedir, '14393.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '14393.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x64_win2016_14393_1():
    basedir = os.path.join(TESTFILES_DIR, 'x64', 'win2016')
    with open(os.path.join(basedir, '14393_1.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '14393_1.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x64_win2016_14393_2():
    basedir = os.path.join(TESTFILES_DIR, 'x64', 'win2016')
    with open(os.path.join(basedir, '14393_2.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '14393_2.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x64_win2016_14393_3():
    basedir = os.path.join(TESTFILES_DIR, 'x64', 'win2016')
    with open(os.path.join(basedir, '14393_3.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '14393_3.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x64_win2019_17763():
    basedir = os.path.join(TESTFILES_DIR, 'x64', 'win2019')
    with open(os.path.join(basedir, '17763.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '17763.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x64_win2019_17763_1():
    basedir = os.path.join(TESTFILES_DIR, 'x64', 'win2019')
    with open(os.path.join(basedir, '17763_1.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '17763_1.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x64_win2022_20348():
    basedir = os.path.join(TESTFILES_DIR, 'x64', 'win2022')
    with open(os.path.join(basedir, '20348.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '20348.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x64_win2022_20348_1():
    basedir = os.path.join(TESTFILES_DIR, 'x64', 'win2022')
    with open(os.path.join(basedir, '20348_1.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '20348_1.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x64_xp_3790():
    basedir = os.path.join(TESTFILES_DIR, 'x64', 'xp')
    with open(os.path.join(basedir, '3790.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '3790.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x86_vista_6002():
    basedir = os.path.join(TESTFILES_DIR, 'x86', 'vista')
    with open(os.path.join(basedir, '6002.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '6002.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x86_win7_7601():
    basedir = os.path.join(TESTFILES_DIR, 'x86', 'win7')
    with open(os.path.join(basedir, '7601.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '7601.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x86_win7_7601_1():
    basedir = os.path.join(TESTFILES_DIR, 'x86', 'win7')
    with open(os.path.join(basedir, '7601_1.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '7601_1.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x86_win10_19043():
    basedir = os.path.join(TESTFILES_DIR, 'x86', 'win10')
    with open(os.path.join(basedir, '19043.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '19043.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x86_win10_14393():
    basedir = os.path.join(TESTFILES_DIR, 'x86', 'win10')
    with open(os.path.join(basedir, '14393.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '14393.dmp'))
    assert compare_jsons(res.to_json(), expected)

def test_x86_win10_14393_1():
    basedir = os.path.join(TESTFILES_DIR, 'x86', 'win10')
    with open(os.path.join(basedir, '14393_1.json'), 'r') as f:
        expected = f.read()
    res = pypykatz.parse_minidump_file(os.path.join(basedir, '14393_1.dmp'))
    assert compare_jsons(res.to_json(), expected)





if __name__ == '__main__':
    test_x64_win7_7601_1()