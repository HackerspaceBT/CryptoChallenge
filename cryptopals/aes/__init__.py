from Crypto.Cipher import AES
from cryptopals.xor import xor_buffers

def ecb_encrypt(key, plaintext):
    return AES.new(key, AES.MODE_ECB).encrypt(plaintext)

def ecb_decrypt(key, ciphertext):
    return AES.new(key, AES.MODE_ECB).decrypt(ciphertext)

def ecb_detect(c):
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

def cbc_encrypt(key, plaintext, iv):
    output = bytes()

    input_blocks = [ plaintext[i:i+16]
                     for i in range(0,len(plaintext),16) ]

    for block in input_blocks:
        iv = ecb_encrypt(xor_buffers(block, iv))
        output += iv

    return output

def cbc_decrypt(key, ciphertext, iv):
    output = bytes()

    input_blocks = [ ciphertext[i:i+16]
                     for i in range(0,len(ciphertext),16) ]

    for block in input_blocks:
        output += xor_buffers(ecb_decrypt(key, block), iv)
        iv = block

    return output
