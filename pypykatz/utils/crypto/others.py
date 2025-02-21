from unicrypto.symmetric import expand_DES_key, MODE_CBC
from unicrypto.symmetric import DES

# https://github.com/frizb/PasswordDecrypts
def vncdecrypt(enc_pw: str or bytes):
    # Define the static key and the zero IV
    key = bytes.fromhex('e84ad660c4721ae0')  # Static key
    iv = b'\x00' * 8   # Zero IV

    if isinstance(enc_pw, str):
        try:
            enc_pw = bytes.fromhex(enc_pw)
        except:
            enc_pw = enc_pw.encode()

    # Create a DES cipher object in CBC mode
    cipher = DES(key, MODE_CBC, IV=iv)

    # Decrypt the data
    decrypted_string = cipher.decrypt(enc_pw)
    decrypted_string = decrypted_string.rstrip(b'\x00')

    try:
        decrypted_string = decrypted_string.decode()
    except:
        decrypted_string = str(decrypted_string)

    print(decrypted_string)
    return decrypted_string