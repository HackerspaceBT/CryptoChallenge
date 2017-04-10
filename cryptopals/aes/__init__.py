import cryptopals.xor
from Crypto.Cipher import AES

def aes_encrypt(key, plaintext):
    return AES.new(key, AES.MODE_ECB).encrypt(plaintext)

def aes_decrypt(key, ciphertext):
    return AES.new(key, AES.MODE_ECB).decrypt(ciphertext)

def detect_ecb(c):
    slices = [ c[s:s+16]
               for s in range(0, len(c), 16) ]

    for i,s in enumerate(slices):
        if slices[i+1:].count(s) > 0:
            return True

    return False
        
def pkcs7_pad(buf, block_len = 16):
    mod = len(buf) % block_len
    pad_len = block_len - mod
    return buf + bytes([pad_len]*pad_len)

def pkcs7_check(buf):
    pad_len = buf[-1]

    if buf[-pad_len:] == bytes([pad_len]*pad_len):
        return True, buf[0:-pad_len]
    else:
        return False, None
