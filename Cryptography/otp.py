#!/usr/bin/env python3
import os, sys    

def bi(b):
    # b - bytes to encode as an integer
    i = b[0]

    for byte in range(0, len(b)):
        i = i << 8
        i = i | b[byte]

    return i

def ib(i, length):
    result = bytes()
    for _ in range(length):
        result = bytes([i & 0xff]) + result
        i = i >> 8
    return result

def encrypt(pfile, kfile, cfile):
    # Read the plaintext file content into bytes object
    b = open(pfile,'rb').read()

    # Convert plaintext bytes to one big integer
    plain_bytes_to_integer = bi(b)

    # Obtain random key the same length as plaintext using os.urandom
    rand_key = os.urandom(len(b))

    # Convert key bytes to one big integer
    key_bytes_to_integer = bi(rand_key)

    # save the key 
    with open(kfile, "wb") as keyfile:
        keyfile.write(rand_key)
    

    # XOR plaintext and key integers
    cipher_text_integer = plain_bytes_to_integer ^ key_bytes_to_integer
    cipher_text_bytes = ib(cipher_text_integer, len(b))
    with open(cfile, "wb") as cfile:
        cfile.write(cipher_text_bytes)

    pass

def decrypt(cfile, kfile, pfile):
    cipher_file_bytes = open(cfile,'rb').read()
    key_file_bytes = open(kfile, 'rb').read()

    cipher_file_integer = bi(cipher_file_bytes)
    key_file_integer = bi(key_file_bytes)

    plain_result_int_xor = cipher_file_integer ^ key_file_integer
    plain_result_bytes = ib(plain_result_int_xor, len(cipher_file_bytes))

    with open(pfile, "wb") as pfile:
        pfile.write(plain_result_bytes)

    pass

def usage():
    print("Usage:")
    print("encrypt <plaintext file> <output key file> <ciphertext output file>")
    print("decrypt <ciphertext file> <key file> <plaintext output file>")
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'encrypt':
    encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'decrypt':
    decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()
