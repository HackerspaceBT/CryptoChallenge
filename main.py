import importlib
from cryptopals import *

def q01():
    print("Challenge 01")
    s1 = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    s2 = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    assert bytes_to_base64(hex_to_bytes(s1)) == s2

def q02():
    print("Challenge 02")
    s1 = '1c0111001f010100061a024b53535009181c'
    s2 = '686974207468652062756c6c277320657965'
    s3 = '746865206b696420646f6e277420706c6179'

    s1b = hex_to_bytes(s1)
    s2b = hex_to_bytes(s2)
    s3b = hex_to_bytes(s3)

    assert(xor.xor_buffers(s1b, s2b) == s3b)

def q03():
    print("Challenge 03")
    s = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    ciphertext = hex_to_bytes(s)
    cipher = xor.find_best_single_xor(ciphertext)[0]
    print("Cipher:    ", cipher)
    print("Plaintext: ", xor.xor_single(ciphertext, cipher))

def q04():
    print("Challenge 04")
    lines = [ hex_to_bytes(l.strip())
              for l in open('data/4.txt').readlines() ]

    best_score = 0
    best_cipher = ''
    best_line = -1
    
    for i,l in enumerate(lines):
        cipher, score = xor.find_best_single_xor(l)
        if score > best_score:
            best_score = score
            best_cipher = cipher
            best_line = i
    print("Best match:", best_line)
    print("Line:      ", xor.xor_single(lines[best_line], best_cipher))
    
def q05():
    print("Challenge 05")
    plaintext = b"""Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"""
    cipher = b"ICE"
    ciphertext = hex_to_bytes("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

    assert(xor.xor_buffers(plaintext, cipher) == ciphertext)

def q06():
    print("Challenge 06")
    assert(xor.hamming_distance(b"this is a test", b"wokka wokka!!!") == 37)

    ciphertext = base64_to_bytes(open('data/6.txt').read().replace('\n', ''))
    cipher = xor.find_best_xor_cipher(ciphertext)

    print("Cipher:    ", cipher)

def q07():
    print("Challenge 07")
    ciphertext = base64_to_bytes(open('data/7.txt').read().replace('\n', ''))
    plaintext  = aes.aes_decrypt(b'YELLOW SUBMARINE', ciphertext)

def q08():
    print("Challenge 08")
    lines = [ base64_to_bytes(l)
              for l in open('data/8.txt').readlines() ]

    for i,l in enumerate(lines):
        if aes.detect_ecb(l):
            print("Line ", i, "is AES-ECB")
            
def allq():
    importlib.reload(cryptopals)
    q01()
    q02()
    q03()
    q04()
    q05()
    q06()
    q07()
    q08()
    
if __name__ == "__main__":
    allq()
