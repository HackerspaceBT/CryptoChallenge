from math import sqrt
import string

letter_score = [f/1000. for f in [
    81.67,
    14.92,
    27.82,
    42.53,
    127.02,
    22.28,
    20.15,
    6.094,
    69.66,
    1.53,
    7.72,
    40.25,
    24.06,
    67.49,
    75.07,
    19.29,
    0.95,
    59.87,
    63.27,
    90.56,
    27.58,
    9.78,
    23.60,
    1.50,
    19.74,
    0.74
]]
digit_score = 0.005
punct_score = 0.001
blank_score = 0
else_score = -1

char_scores = [else_score]*256
for c in [ord(c) for c in string.ascii_lowercase]:
    char_scores[c] = sqrt(letter_score[c-ord('a')])
for c in [ord(c) for c in string.ascii_uppercase]:
    char_scores[c] = sqrt(letter_score[c-ord('A')])
for c in [ord(c) for c in string.digits]:
    char_scores[c] = digit_score
for c in [ord(c) for c in string.punctuation]:
    char_scores[c] = punct_score
for c in [ord(c) for c in string.whitespace]:
    char_scores[c] = blank_score
char_scores[ord(' ')] = 0.1

def xor_buffers(a, b):
    if len(a) < len(b):
        a,b = b,a

    la = len(a)
    lb = len(b)
        
    return bytes([a[i]^b[i%lb] for i in range(la)])

def xor_single(a, b):
    return bytes([c^b for c in a])

def find_best_single_xor(s):
    def score_char(c):
        return char_scores[c]

    def score_buffer(b):
        return sum([score_char(c) for c in b])

    cipher_scores = [ score_buffer(xor_single(s, i)) for i in range(256) ]

    return cipher_scores.index(max(cipher_scores)), max(cipher_scores)

def _popcount(c):
    n=0
    for i in range(8):
        if c & (2**i) > 0:
            n += 1
    return n

popcnt = [ _popcount(c) for c in range(256) ]

def hamming_distance(a, b):
    return sum([popcnt[a[i]^b[i]] for i in range(min(len(a), len(b)))])

def find_best_xor_cipher(s):
    best_score = 8 * len(s)
    best_keysize = -1
    for keysize in range(2,45):
        distances = [
            hamming_distance(s[keysize*i:keysize*(i+1)],
                             s[keysize*(i+1):keysize*(i+2)])
            for i in range(0, len(s)//keysize-1, 2) ]
        score = sum(distances) / keysize / len(distances)

        if score < best_score:
            best_keysize = keysize
            best_score   = score

    return bytes([ find_best_single_xor(s[i::best_keysize])[0]
                   for i in range(best_keysize) ])
