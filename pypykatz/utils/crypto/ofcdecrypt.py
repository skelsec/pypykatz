# Python implementation of the Trend Micro Password Decryptor
# This script decrypts encrypted passwords stored in the TrendMicro OfficeScan "odscan.ini" file
#
# original code from https://aluigi.altervista.org/pwdrec.htm#trendmicropwd
# original code was developed by Luigi Auriemma in the year of 2008
#
# This script was ported to Python by Tamas Jos @skelsec
#
# TODO: the script is missing the trendmicro_PWDDecrypt function, which doesn't seem to be in use anymore


from unicrypto.symmetric import AES, cipherMODE
import array
import os
import re

def trendmicro_build_key(pwd1, pwd2):
    o = [513,1027,1541,2055]
    pwd1 = [x for x in pwd1]
    pwd2 = [x for x in pwd2]
    idxa = 0
    idxb = 0

    a = pwd1[idxa]
    b = pwd2[idxb]

    x = 0x7f3b
    for i in range(4):
        if a == 0 and b == 0:
            break
        x ^= ((a | (b << 8)) ^ 0x6b2c) & 0xffff
        t = i
        if i==1:
            t = 2
        elif i==2:
            t = 1
        
        o[t] ^= (x & 0xffff)
        
        idxa += 1
        idxb += 1
        if idxa >= len(pwd1):
            a = 0
        else:
            a = pwd1[idxa]
        if idxb >= len(pwd2):
            b = 0
        else:
            b = pwd2[idxb]

    return b''.join([int.to_bytes(x, 2, byteorder='little', signed=False) for x in o]) 

def trendmicro_crypt(encdata:str):
    multistr = 0
    results = []
    while len(encdata) > 0:
        multistr += 1
        tablex = [0] * 768
        if encdata[0] == '!':
            encdata = encdata[1:]
        blocks = int(encdata[0])
        blocklen = bytes.fromhex(encdata[1:3])[0]
        encdata = encdata[3:]

        key = trendmicro_build_key(b"Windows7621673NT", b"Virus3761267Trend")
        res = ''
        tablex = trendmicro_crypt1(tablex, key)
        for i in range(blocks):
            i =i*16
            blockdata = bytes.fromhex(encdata[i:i+16])
            res += trendmicro_crypt2(tablex, blockdata)
        
        res = res[:blocklen]
        encdata = encdata[blocks*16:]
        rescrc = int.from_bytes(bytes.fromhex(encdata[:8]), byteorder='big', signed=False)
        encdata = encdata[8:]
        
        # crc is taken over all 4 byte aligned blocks (not the last block if it's not aligned)
        crcblocklen = (blocklen//4)*4
        crc = 0x4f627a3b
        x = array.array('I', res.encode()[:crcblocklen])
        for c in x:
            crc = (crc ^ c) & 0xffffffff
        
        if crc != rescrc:
            res = '!!!CRC MISMATCH!!!' + res

        if multistr == 1:
            res = res[3:]
        results.append(res)
    return ''.join(results)

def trendmicro_crypt2(tablex, blockdata, encdec:bool=False):
    table1 = b"\x07\x02\x06\x02\x05\x02\x04\x02\x03\x02\x02\x02\x01\x02\x00\x02" +\
        b"\x07\x08\x06\x08\x05\x08\x04\x08\x03\x08\x02\x08\x01\x08\x00\x08" +\
        b"\x07\x20\x06\x20\x05\x20\x04\x20\x03\x20\x02\x20\x01\x20\x00\x20" +\
        b"\x07\x80\x06\x80\x05\x80\x04\x80\x03\x80\x02\x80\x01\x80\x00\x80" +\
        b"\x07\x01\x06\x01\x05\x01\x04\x01\x03\x01\x02\x01\x01\x01\x00\x01" +\
        b"\x07\x04\x06\x04\x05\x04\x04\x04\x03\x04\x02\x04\x01\x04\x00\x04" +\
        b"\x07\x10\x06\x10\x05\x10\x04\x10\x03\x10\x02\x10\x01\x10\x00\x10" +\
        b"\x07\x40\x06\x40\x05\x40\x04\x40\x03\x40\x02\x40\x01\x40\x00\x40"
    table2 = b"\x1f\x00\x01\x02\x03\x04\x03\x04\x05\x06\x07\x08\x07\x08\x09\x0a" +\
        b"\x0b\x0c\x0b\x0c\x0d\x0e\x0f\x10\x0f\x10\x11\x12\x13\x14\x13\x14" +\
        b"\x15\x16\x17\x18\x17\x18\x19\x1a\x1b\x1c\x1b\x1c\x1d\x1e\x1f\x00"
    table3 = b"\x0e\x04\x0d\x01\x02\x0f\x0b\x08\x03\x0a\x06\x0c\x05\x09\x00\x07" +\
        b"\x00\x0f\x07\x04\x0e\x02\x0d\x01\x0a\x06\x0c\x0b\x09\x05\x03\x08" +\
        b"\x04\x01\x0e\x08\x0d\x06\x02\x0b\x0f\x0c\x09\x07\x03\x0a\x05\x00" +\
        b"\x0f\x0c\x08\x02\x04\x09\x01\x07\x05\x0b\x03\x0e\x0a\x00\x06\x0d" +\
        b"\x0f\x01\x08\x0e\x06\x0b\x03\x04\x09\x07\x02\x0d\x0c\x00\x05\x0a" +\
        b"\x03\x0d\x04\x07\x0f\x02\x08\x0e\x0c\x00\x01\x0a\x06\x09\x0b\x05" +\
        b"\x00\x0e\x07\x0b\x0a\x04\x0d\x01\x05\x08\x0c\x06\x09\x03\x02\x0f" +\
        b"\x0d\x08\x0a\x01\x03\x0f\x04\x02\x0b\x06\x07\x0c\x00\x05\x0e\x09" +\
        b"\x0a\x00\x09\x0e\x06\x03\x0f\x05\x01\x0d\x0c\x07\x0b\x04\x02\x08" +\
        b"\x0d\x07\x00\x09\x03\x04\x06\x0a\x02\x08\x05\x0e\x0c\x0b\x0f\x01" +\
        b"\x0d\x06\x04\x09\x08\x0f\x03\x00\x0b\x01\x02\x0c\x05\x0a\x0e\x07" +\
        b"\x01\x0a\x0d\x00\x06\x09\x08\x07\x04\x0f\x0e\x03\x0b\x05\x02\x0c" +\
        b"\x07\x0d\x0e\x03\x00\x06\x09\x0a\x01\x02\x08\x05\x0b\x0c\x04\x0f" +\
        b"\x0d\x08\x0b\x05\x06\x0f\x00\x03\x04\x07\x02\x0c\x01\x0a\x0e\x09" +\
        b"\x0a\x06\x09\x00\x0c\x0b\x07\x0d\x0f\x01\x03\x0e\x05\x02\x08\x04" +\
        b"\x03\x0f\x00\x06\x0a\x01\x0d\x08\x09\x04\x05\x0b\x0c\x07\x02\x0e" +\
        b"\x02\x0c\x04\x01\x07\x0a\x0b\x06\x08\x05\x03\x0f\x0d\x00\x0e\x09" +\
        b"\x0e\x0b\x02\x0c\x04\x07\x0d\x01\x05\x00\x0f\x0a\x03\x09\x08\x06" +\
        b"\x04\x02\x01\x0b\x0a\x0d\x07\x08\x0f\x09\x0c\x05\x06\x03\x00\x0e" +\
        b"\x0b\x08\x0c\x07\x01\x0e\x02\x0d\x06\x0f\x00\x09\x0a\x04\x05\x03" +\
        b"\x0c\x01\x0a\x0f\x09\x02\x06\x08\x00\x0d\x03\x04\x0e\x07\x05\x0b" +\
        b"\x0a\x0f\x04\x02\x07\x0c\x09\x05\x06\x01\x0d\x0e\x00\x0b\x03\x08" +\
        b"\x09\x0e\x0f\x05\x02\x08\x0c\x03\x07\x00\x04\x0a\x01\x0d\x0b\x06" +\
        b"\x04\x03\x02\x0c\x09\x05\x0f\x0a\x0b\x0e\x01\x07\x06\x00\x08\x0d" +\
        b"\x04\x0b\x02\x0e\x0f\x00\x08\x0d\x03\x0c\x09\x07\x05\x0a\x06\x01" +\
        b"\x0d\x00\x0b\x07\x04\x09\x01\x0a\x0e\x03\x05\x0c\x02\x0f\x08\x06" +\
        b"\x01\x04\x0b\x0d\x0c\x03\x07\x0e\x0a\x0f\x06\x08\x00\x05\x09\x02" +\
        b"\x06\x0b\x0d\x08\x01\x04\x0a\x07\x09\x05\x00\x0f\x0e\x02\x03\x0c" +\
        b"\x0d\x02\x08\x04\x06\x0f\x0b\x01\x0a\x09\x03\x0e\x05\x00\x0c\x07" +\
        b"\x01\x0f\x0d\x08\x0a\x03\x07\x04\x0c\x05\x06\x0b\x00\x0e\x09\x02" +\
        b"\x07\x0b\x04\x01\x09\x0c\x0e\x02\x00\x06\x0a\x0d\x0f\x03\x05\x08" +\
        b"\x02\x01\x0e\x07\x04\x0a\x08\x0d\x0f\x0c\x09\x00\x03\x05\x06\x0b"
    table4 = b"\x0f\x06\x13\x14\x1c\x0b\x1b\x10\x00\x0e\x16\x19\x04\x11\x1e\x09" +\
        b"\x01\x07\x17\x0d\x1f\x1a\x02\x08\x12\x0c\x1d\x05\x15\x0a\x03\x18"
    table5 = b"\x27\x07\x2f\x0f\x37\x17\x3f\x1f\x26\x06\x2e\x0e\x36\x16\x3e\x1e" +\
        b"\x25\x05\x2d\x0d\x35\x15\x3d\x1d\x24\x04\x2c\x0c\x34\x14\x3c\x1c" +\
        b"\x23\x03\x2b\x0b\x33\x13\x3b\x1b\x22\x02\x2a\x0a\x32\x12\x3a\x1a" +\
        b"\x21\x01\x29\x09\x31\x11\x39\x19\x20\x00\x28\x08\x30\x10\x38\x18"

    tmp = [0] * 0x60
    tmp2 = [0] * 0x30
    bck = [0] * 0x20

    for i in range(0x40):
        tmp[i] = 1 if (blockdata[table1[i * 2]] & table1[(i * 2) + 1]) else 0

    
    for i in range(0x10):
        bck = tmp[0x20:0x40]

        if encdec is True:
            t = i
        else:
            t = 0xf - i

        for j in range(0x30):
            tmp2[j] = tmp[0x20 + table2[j]] ^ tablex[(t * 0x30) + j]

        
        for j in range(8):
            t = j*6
            c = (tmp2[t] << 5) | (tmp2[t + 1] << 3) | (tmp2[t + 2] << 2) | (tmp2[t + 3] << 1) | tmp2[t + 4] | (tmp2[t + 5] << 4)
            c = table3[(j << 6) + c]
            t = j << 2
            tmp[0x40 + t] = (c >> 3) & 1
            tmp[0x41 + t] = (c >> 2) & 1
            tmp[0x42 + t] = (c >> 1) & 1
            tmp[0x43 + t] = c & 1
        
        
        for j in range(0x20):
            tmp[0x20 + j] = tmp[j] ^ tmp[0x40 + table4[j]]
        
        tmp = bck + tmp[0x20:]
    
    
    bck = tmp[0x20:0x40]
    tmp = tmp[:0x20] + tmp[:0x20] + tmp[0x40:]
    tmp = bck + tmp[0x20:]

    tdata = [x for x in blockdata]
    t = 0
    for i in range(8):
        tdata[i] = 0
        j = 1
        while j <= 0x80:
            if tmp[table5[t]]:
                tdata[i] |= j
            t += 1
            j = j*2

    tdata = ''.join(chr(x) for x in tdata)
    return tdata


def trendmicro_crypt1(tablex, key):
    table1 = b"\x07\x01\x06\x01\x05\x01\x04\x01\x03\x01\x02\x01\x01\x01\x00\x01" +\
        b"\x07\x02\x06\x02\x05\x02\x04\x02\x03\x02\x02\x02\x01\x02\x00\x02" +\
        b"\x07\x04\x06\x04\x05\x04\x04\x04\x03\x04\x02\x04\x01\x04\x00\x04" +\
        b"\x07\x08\x06\x08\x05\x08\x04\x08\x07\x40\x06\x40\x05\x40\x04\x40" +\
        b"\x03\x40\x02\x40\x01\x40\x00\x40\x07\x20\x06\x20\x05\x20\x04\x20" +\
        b"\x03\x20\x02\x20\x01\x20\x00\x20\x07\x10\x06\x10\x05\x10\x04\x10" +\
        b"\x03\x10\x02\x10\x01\x10\x00\x10\x03\x08\x02\x08\x01\x08\x00\x08" 

    table2 = b"\x01\x01\x02\x02\x02\x02\x02\x02\x01\x02\x02\x02\x02\x02\x02\x01"
    table3 = b"\x0d\x10\x0a\x17\x00\x04\x02\x1b\x0e\x05\x14\x09\x16\x12\x0b\x03" +\
        b"\x19\x07\x0f\x06\x1a\x13\x0c\x01\x28\x33\x1e\x24\x2e\x36\x1d\x27" +\
        b"\x32\x2c\x20\x2f\x2b\x30\x26\x37\x21\x34\x2d\x29\x31\x23\x1c\x1f"

    tmp = [0] * 0x38
    for i in range(0x38):
        kl = key[table1[i * 2]]
        tl = table1[(i * 2) + 1]
        kt = kl & tl
        tmp[i] = 1 if kt else 0

    c = 0
    for i in range(0x10):
        c += table2[i]
        for j in range(0x30):
            t = table3[j]
            if t < 0x1C:
                r = 0
            else:
                r = 0x1C
                t -= 0x1C
            t += c
            if t >= 0x1C:
                t -= 0x1C
            t += r
            tablex[(i * 0x30) + j] = tmp[t]
    return tablex
    
def trendmicro_cryptex(encdata:str):
    # static AES key and IV
    # security is top notch
    key = b"\xeb\x06\xe9\xc7\x6c\x16\x1d\x6c\x89\x70\x3d\xfc\x72\x53\xff\xdd\x71\xad\x07\xbf\x12\xf4\xa2\xe7\xa0\x89\xfc\x7c\xa6\xca\x4b\x73"
    iv = b"\x15\x69\x2e\xfc\x39\x89\x4a\xba\x9b\x62\xce\x66\xc9\x05\x12\xae"

    dec = AES(key, cipherMODE.CBC, iv).decrypt(bytes.fromhex(encdata))
    # remove pkcs1 padding from decrypted data
    dec = dec[:-dec[-1]]
    return dec[3:].decode('utf-8')

def trendmicro_decrypt(encdata:str):
    if encdata.startswith('!CRYPT!') is True:
        return trendmicro_crypt(encdata[7:])
    if encdata.startswith('!CRYPTEX!') is True:
        return trendmicro_cryptex(encdata[9:])
    if encdata.startswith('!CRYPTEX3!') is True:
        return trendmicro_cryptex(encdata[10:])
    if encdata.startswith('!CRYPTNG!') is True:
        return 'Decrypting CRYPTNG is not supported'

def parse_ofscan_ini_file(filepath):
    pattern = re.compile(r'^([^=]+?)=\s*((!CRYPTEX!|!CRYPT!|!CRYPTEX3!|!CRYPTNG!)[^=]+)$')
    result = []
    with open(filepath, 'r', encoding='latin-1') as f:
        for line in f:
            line = line.strip()
            if line == '':
                continue
            match = pattern.match(line)
            if match:
                result.append((match.group(1), match.group(2)))
        return result

def ofscan_decrypt_data(filepath_or_data):
    if os.path.isfile(filepath_or_data):
        lines = parse_ofscan_ini_file(filepath_or_data)
    else:
        lines = ['RESULT:', filepath_or_data]

    results = []
    for line in lines:
        try:
            decdata = trendmicro_decrypt(line[1])
            if decdata is None:
                continue
            if decdata.startswith('!CRYPTEX!') is True:
                decdata = trendmicro_decrypt(decdata)
            results.append((line[0], decdata))
        except Exception as e:
            results.append((line[0], 'Failed to decrypt: %s Reason: %s' % (line[1], e)))
    return results

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Decrypt TrendMicro ofscan.ini file')
    parser.add_argument('filepath', help='ofscan.ini file path or string beginning with !CRYPT! or !CRYPTEX! or !CRYPTEX3!')
    args = parser.parse_args()

    results = ofscan_decrypt_data(args.filepath)
    for result in results:
        print('%s: %s' % (result[0], result[1]))

if __name__ == '__main__':
    main()