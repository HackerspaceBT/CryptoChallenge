import base64

import cryptopals.xor

def base64_to_bytes(ba):
    return base64.b64decode(ba)

def bytes_to_base64(ba):
    return base64.b64encode(ba)

def hex_to_bytes(h):
    return bytes.fromhex(h)

def bytes_to_hex(b):
    return b.hex()

