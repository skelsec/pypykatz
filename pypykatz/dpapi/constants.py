import enum

# https://eljay.github.io/directx-sys/winapi/wincrypt/index.html
# https://doxygen.reactos.org/d7/d4a/wincrypt_8h.html
# impacket dpapi.py

from hashlib import sha1 as SHA1
from hashlib import sha512 as SHA512
from pypykatz.crypto.unified.aes import AES
from pypykatz.crypto.unified.des3 import DES3
from pypykatz.crypto.unified.common import SYMMETRIC_MODE


# Algorithm classes
ALG_CLASS_ANY                   = (0)
ALG_CLASS_SIGNATURE             = (1 << 13)
ALG_CLASS_MSG_ENCRYPT           = (2 << 13)
ALG_CLASS_DATA_ENCRYPT          = (3 << 13)
ALG_CLASS_HASH                  = (4 << 13)
ALG_CLASS_KEY_EXCHANGE          = (5 << 13)
ALG_CLASS_ALL                   = (7 << 13)

# Algorithm types
ALG_TYPE_ANY                    = (0)
ALG_TYPE_DSS                    = (1 << 9)
ALG_TYPE_RSA                    = (2 << 9)
ALG_TYPE_BLOCK                  = (3 << 9)
ALG_TYPE_STREAM                 = (4 << 9)
ALG_TYPE_DH                     = (5 << 9)
ALG_TYPE_SECURECHANNEL          = (6 << 9)
ALG_SID_ANY                     = (0)
ALG_SID_RSA_ANY                 = 0
ALG_SID_RSA_PKCS                = 1
ALG_SID_RSA_MSATWORK            = 2
ALG_SID_RSA_ENTRUST             = 3
ALG_SID_RSA_PGP                 = 4
ALG_SID_DSS_ANY                 = 0
ALG_SID_DSS_PKCS                = 1
ALG_SID_DSS_DMS                 = 2
ALG_SID_ECDSA                   = 3

# Block cipher sub ids
ALG_SID_DES                     = 1
ALG_SID_3DES                    = 3
ALG_SID_DESX                    = 4
ALG_SID_IDEA                    = 5
ALG_SID_CAST                    = 6
ALG_SID_SAFERSK64               = 7
ALG_SID_SAFERSK128              = 8
ALG_SID_3DES_112                = 9
ALG_SID_CYLINK_MEK              = 12
ALG_SID_RC5                     = 13
ALG_SID_AES_128                 = 14
ALG_SID_AES_192                 = 15
ALG_SID_AES_256                 = 16
ALG_SID_AES                     = 17
ALG_SID_SKIPJACK                = 10
ALG_SID_TEK                     = 11

CRYPT_MODE_CBCI                 = 6       # ANSI CBC Interleaved
CRYPT_MODE_CFBP                 = 7       # ANSI CFB Pipelined
CRYPT_MODE_OFBP                 = 8       # ANSI OFB Pipelined
CRYPT_MODE_CBCOFM               = 9       # ANSI CBC + OF Masking
CRYPT_MODE_CBCOFMI              = 10      # ANSI CBC + OFM Interleaved

ALG_SID_RC2                     = 2
ALG_SID_RC4                     = 1
ALG_SID_SEAL                    = 2

# Diffie - Hellman sub - ids
ALG_SID_DH_SANDF                = 1
ALG_SID_DH_EPHEM                = 2
ALG_SID_AGREED_KEY_ANY          = 3
ALG_SID_KEA                     = 4
ALG_SID_ECDH                    = 5

# Hash sub ids
ALG_SID_MD2                     = 1
ALG_SID_MD4                     = 2
ALG_SID_MD5                     = 3
ALG_SID_SHA                     = 4
ALG_SID_SHA1                    = 4
ALG_SID_MAC                     = 5
ALG_SID_RIPEMD                  = 6
ALG_SID_RIPEMD160               = 7
ALG_SID_SSL3SHAMD5              = 8
ALG_SID_HMAC                    = 9
ALG_SID_TLS1PRF                 = 10
ALG_SID_HASH_REPLACE_OWF        = 11
ALG_SID_SHA_256                 = 12
ALG_SID_SHA_384                 = 13
ALG_SID_SHA_512                 = 14

# secure channel sub ids
ALG_SID_SSL3_MASTER             = 1
ALG_SID_SCHANNEL_MASTER_HASH    = 2
ALG_SID_SCHANNEL_MAC_KEY        = 3
ALG_SID_PCT1_MASTER             = 4
ALG_SID_SSL2_MASTER             = 5
ALG_SID_TLS1_MASTER             = 6
ALG_SID_SCHANNEL_ENC_KEY        = 7
ALG_SID_ECMQV                   = 1

class ALGORITHMS(enum.IntFlag):
    CALG_MD2                = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD2)
    CALG_MD4                = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD4)
    CALG_MD5                = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD5)
    CALG_SHA                = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA)
    CALG_SHA1               = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA1)
    CALG_RSA_SIGN           = (ALG_CLASS_SIGNATURE | ALG_TYPE_RSA | ALG_SID_RSA_ANY)
    CALG_DSS_SIGN           = (ALG_CLASS_SIGNATURE | ALG_TYPE_DSS | ALG_SID_DSS_ANY)
    CALG_NO_SIGN            = (ALG_CLASS_SIGNATURE | ALG_TYPE_ANY | ALG_SID_ANY)
    CALG_RSA_KEYX           = (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_RSA|ALG_SID_RSA_ANY)
    CALG_DES                = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_DES)
    CALG_3DES_112           = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_3DES_112)
    CALG_3DES               = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_3DES)
    CALG_DESX               = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_DESX)
    CALG_RC2                = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_RC2)
    CALG_RC4                = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_STREAM|ALG_SID_RC4)
    CALG_SEAL               = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_STREAM|ALG_SID_SEAL)
    CALG_DH_SF              = (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_DH_SANDF)
    CALG_DH_EPHEM           = (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_DH_EPHEM)
    CALG_AGREEDKEY_ANY      = (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_AGREED_KEY_ANY)
    CALG_KEA_KEYX           = (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_KEA)
    CALG_HUGHES_MD5         = (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_ANY|ALG_SID_MD5)
    CALG_SKIPJACK           = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_SKIPJACK)
    CALG_TEK                = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_TEK)
    CALG_SSL3_SHAMD5        = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SSL3SHAMD5)
    CALG_SSL3_MASTER        = (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_SSL3_MASTER)
    CALG_SCHANNEL_MASTER_HASH   = (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_SCHANNEL_MASTER_HASH)
    CALG_SCHANNEL_MAC_KEY   = (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_SCHANNEL_MAC_KEY)
    CALG_SCHANNEL_ENC_KEY   = (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_SCHANNEL_ENC_KEY)
    CALG_PCT1_MASTER        = (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_PCT1_MASTER)
    CALG_SSL2_MASTER        = (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_SSL2_MASTER)
    CALG_TLS1_MASTER        = (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_TLS1_MASTER)
    CALG_RC5                = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_RC5)
    CALG_HMAC               = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HMAC)
    CALG_TLS1PRF            = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_TLS1PRF)
    CALG_HASH_REPLACE_OWF   = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HASH_REPLACE_OWF)
    CALG_AES_128            = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_AES_128)
    CALG_AES_192            = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_AES_192)
    CALG_AES_256            = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_AES_256)
    CALG_AES                = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_AES)
    CALG_SHA_256            = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256)
    CALG_SHA_384            = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_384)
    CALG_SHA_512            = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_512)
    CALG_ECDH               = (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_ECDH)
    CALG_ECMQV              = (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | ALG_SID_ECMQV)
    CALG_ECDSA              = (ALG_CLASS_SIGNATURE | ALG_TYPE_DSS | ALG_SID_ECDSA)
	
ALGORITHMS_DATA = {
    # Algorithm: key/SaltLen, CryptHashModule, Mode, IVLen, BlockSize
    ALGORITHMS.CALG_SHA: (160//8, SHA1, None, None, 512//8),
    ALGORITHMS.CALG_HMAC: (160//8, SHA512, None, None, 512//8),
    ALGORITHMS.CALG_3DES: (192//8, DES3, SYMMETRIC_MODE.CBC, 64//8),
    ALGORITHMS.CALG_SHA_512: (128//8, SHA512, None, None, 1024//8),
    ALGORITHMS.CALG_AES_256: (256//8, AES, SYMMETRIC_MODE.CBC,128//8), #CBC is already in the object...
}
	
	
class FLAGS(enum.IntFlag):
    CRYPTPROTECT_UI_FORBIDDEN = 0x1
    CRYPTPROTECT_LOCAL_MACHINE = 0x4
    CRYPTPROTECT_CRED_SYNC = 0x8
    CRYPTPROTECT_AUDIT = 0x10
    CRYPTPROTECT_VERIFY_PROTECTION = 0x40
    CRYPTPROTECT_CRED_REGENERATE = 0x80
    CRYPTPROTECT_SYSTEM = 0x20000000