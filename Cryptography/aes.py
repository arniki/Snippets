#!/usr/bin/env python3

import hmac  
import hashlib
from hashlib import pbkdf2_hmac
from Cryptodome.Util.strxor import strxor
from Cryptodome.Cipher import AES
import time
import os
import sys
from pyasn1.codec.der import decoder

# $ sudo apt-get install python3-pycryptodome
sys.path = sys.path[1:]  # removes current directory from aes.py search path


# ==== ASN1 encoder start ====

def asn1_len(value_bytes):
    # helper function - should be used in other functions to calculate length octet(s)
    # value_bytes - bytes containing TLV value byte(s)
    # returns length (L) byte(s) for TLV
    n = len(value_bytes)
    if n < 128:
        return bytes([n])
    else:
        length_bytes = []
        while n > 0:
            length_bytes.append(n & 0xff)
            n >>= 8
        length_bytes.reverse()
        length_indicator = bytes([0x80 | len(length_bytes)])
        return length_indicator + bytes(length_bytes)

def asn1_null():
    # returns DER encoding of NULL
    return b'\x05\x00'

def asn1_objectidentifier(oid):
    # oid - list of integers representing OID (e.g., [1,2,840,123123])
    # returns DER encoding of OBJECTIDENTIFIER
    oid_bytes = bytes([oid[0] * 40 + oid[1]])
    for i in oid[2:]:
        val_bytes = []
        val_bytes.append(0x80 | (i & 0x7f))
        i >>= 7
        while i > 0:
            val_bytes.append(0x80 | (i & 0x7f))
            i >>= 7
        val_bytes.reverse()
        val_bytes[-1] &= 0x7f
        oid_bytes += bytes(val_bytes)
    return b'\x06' + asn1_len(oid_bytes) + oid_bytes

def asn1_integer(i):
    # i - arbitrary integer (of type 'int' or 'long')
    # returns DER encoding of INTEGER
    if i == 0:
        return b'\x02\x01\x00'

    bytestring = b''
    while i > 0:
        bytestring = bytes([i & 0xff]) + bytestring
        i >>= 8

    if bytestring[0] & 0x80:
        bytestring = b'\x00' + bytestring
    return b'\x02' + asn1_len(bytestring) + bytestring

def asn1_octetstring(value_bytes):
    # octets - arbitrary byte string (e.g., b"abc\x01")
    # returns DER encoding of OCTETSTRING
    return bytes([0x04]) + asn1_len(value_bytes) + value_bytes

def asn1_sequence(der_bytes):
    # der - DER bytes to encapsulate into sequence
    # returns DER encoding of SEQUENCE
    return b'\x30' + asn1_len(der_bytes) + der_bytes

# ==== ASN1 encoder end ====


# this function benchmarks how many PBKDF2 iterations
# can be performed in one second on the machine it is executed
def benchmark():

    # Define the number of iterations to perform
    iter_count = 10000

    # Define the password and salt to use for PBKDF2
    password = b"thisIsAPasswordOfReasonableLength"
    salt = os.urandom(8)

    # Perform the PBKDF2 iterations and measure the time it takes
    start_time = time.time()
    hashlib.pbkdf2_hmac('sha1', password, salt, iter_count, 48)
    end_time = time.time()

    # calculate number of iterations that can be performed in 1 second
    single_iteration_time = (end_time - start_time)
    iter = int((1 / single_iteration_time) * iter_count)


    print("[+] Benchmark: %s PBKDF2 iterations in 1 second" % (iter))

    return iter  # returns number of iterations that can be performed in 1 second

def encrypt(pfile, cfile):
    # benchmarking
    iter_count = benchmark()

    

    # asking for a password
    password = input("[?] Enter password: ").encode()
    # derieving keys
    salt = os.urandom(8)
    dk = hashlib.pbkdf2_hmac('sha1', password, salt, iter_count, 48)
    aes_key = dk[:16]
    hmac_key = dk[16:]
    iv = os.urandom(16)
    iv_current = iv
    # reading plaintext
    with open(pfile, 'rb') as f:
        plain_bytes = f.read()
    
    # padding plaintext
    plaintext_len = len(plain_bytes)
    padding_size = 16 - (plaintext_len % 16)
    padding = (b"%c" % padding_size) * padding_size
    plain_bytes += padding
    # encrypting padded plaintext
    cipher = AES.new(aes_key, AES.MODE_ECB)
    iv = os.urandom(16)
    block_count = plaintext_len // 16 + 1
    iv_current = iv
    ciphertext_bytes = b""

    for x in range(block_count):
        byte_index = x * 16
        plaintext_block = plain_bytes[byte_index:byte_index + 16]
        ciphertext_bytes += cipher.encrypt(strxor(plaintext_block, iv_current))
        iv_current = ciphertext_bytes[byte_index:byte_index + 16]

    # MAC calculation (iv+ciphertext)
    mac_digest = hmac.new(hmac_key, iv + ciphertext_bytes, hashlib.sha256).digest()

    # constructing DER header
    der = asn1_sequence(
            asn1_sequence(
                asn1_octetstring(salt)+ # salt
                asn1_integer(iter_count)+ # iteration count
                asn1_integer(48)) +  # key length
            asn1_sequence(
                asn1_objectidentifier([2,16,840,1,101,3,4,1,2])+ # AES-128-CBC
                asn1_octetstring(iv)) + # initialization vector
            asn1_sequence(
                asn1_sequence(
                    asn1_objectidentifier([2,16,840,1,101,3,4,2,1])+ # HMAC-SHA256
                    asn1_null())+
                asn1_octetstring(mac_digest))) # MAC digest

    # writing DER header and ciphertext to file
    f = open(cfile, 'wb')
    f.write(der + ciphertext_bytes)
    f.close()
    pass

def decrypt(cfile, pfile):

    # reading DER header and ciphertext
    f = open(cfile, 'rb')
    contents = f.read()
    asn1, ciphertext = decoder.decode(contents)
    f.close()
    # asking for a password
    password = input("[?] Enter password: ").encode()

    # derieving keys
    salt = bytes(asn1[0][0])
    iter_count = asn1[0][1]
    key_length = asn1[0][2]
    dk = hashlib.pbkdf2_hmac('sha1', password, salt, iter_count, key_length)
    aes_key = dk[:16]
    hmac_key = dk[16:]
    iv_current = bytes(asn1[1][1])


    mac_digest=bytes(asn1[2][1])

    # reading ciphertext
    ciphertext_blocks = [ciphertext[i:i+16]for i in range(0, len(ciphertext), 16)]

    # before decryption checking MAC (iv+ciphertext)
    computed_mac = hmac.new(hmac_key, iv_current+ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(computed_mac, mac_digest):
        print("[-] HMAC verification failure: wrong password or modified ciphertext!")
        return

    # decrypting ciphertext
    plaintext = b''
    for ciphertext_block in ciphertext_blocks:
        cipher = AES.new(aes_key, AES.MODE_ECB)
        plaintext_block = strxor(cipher.decrypt(ciphertext_block), iv_current)
        plaintext += plaintext_block
        iv_current = ciphertext_block
    # removing padding
    padding_len = plaintext[-1]
    plaintext = plaintext[:-padding_len]
    # writing plaintext to file
    f = open(pfile, 'wb')
    f.write(plaintext)
    f.close()


    pass


def usage():
    print("Usage:")
    print("-encrypt <plaintextfile> <ciphertextfile>")
    print("-decrypt <ciphertextfile> <plaintextfile>")
    sys.exit(1)


if len(sys.argv) != 4:
    usage()
elif sys.argv[1] == '-encrypt':
    encrypt(sys.argv[2], sys.argv[3])
elif sys.argv[1] == '-decrypt':
    decrypt(sys.argv[2], sys.argv[3])
else:
    usage()