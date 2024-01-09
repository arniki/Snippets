#!/usr/bin/env python3

import codecs, hashlib, os, sys 
from pyasn1.codec.der import decoder


def ib(i, length=False):
    # converts integer to bytes
    b = b''
    if length==False:
        length = (i.bit_length()+7)//8
    for _ in range(length):
        b = bytes([i & 0xff]) + b
        i >>= 8
    return b

def bi(b):
    # converts bytes to integer
    i = 0
    for byte in b:
        i <<= 8
        i |= byte
    return i

#==== ASN1 encoder start ====
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

def asn1_null():
    # returns DER encoding of NULL
    return b'\x05\x00'

def asn1_octetstring(value_bytes):
    # octets - arbitrary byte string (e.g., b"abc\x01")
    # returns DER encoding of OCTETSTRING
    return bytes([0x04]) + asn1_len(value_bytes) + value_bytes

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

def asn1_sequence(der_bytes):
    # der - DER bytes to encapsulate into sequence
    # returns DER encoding of SEQUENCE
    return b'\x30' + asn1_len(der_bytes) + der_bytes

#==== ASN1 encoder end ====

def pem_to_der(content):
    # converts PEM content to DER
    if content.startswith(b'-----BEGIN'):
        content = content.replace(b'-----BEGIN PRIVATE KEY-----', b'')
        content = content.replace(b'-----BEGIN PUBLIC KEY-----', b'')
        content = content.replace(b'-----END PRIVATE KEY-----', b'')
        content = content.replace(b'-----END PUBLIC KEY-----', b'')
        content = content.replace(b'\n', b'')
        content = codecs.decode(content, 'base64')
    return content

def get_pubkey(filename):
    # reads public key file encoded using SubjectPublicKeyInfo structure and returns (N, e)
    with open(filename, 'rb') as f:
        pem_contents = f.read()

    # DER-decode the DER to get RSAPublicKey DER structure, which is encoded as BITSTRING
    der_contents = pem_to_der(pem_contents)
    der_contents = decoder.decode(der_contents)
    bitstring = der_contents[0][1]
    # convert BITSTRING to bytestring
    bytestring = bitstring.asOctets()
    # DER-decode the bytestring (which is actually DER) and return (N, e)
    pubkey = decoder.decode(bytestring)[0]
    # pubkey[0] is N  (modulus)
    # pubkey[1] is e  (public exponent)
    return int(pubkey[0]), int(pubkey[1])

def get_privkey(filename):
    # reads private key file encoded using PrivateKeyInfo (PKCS#8) structure and returns (N, d)
    with open(filename, "rb") as f:
        priv_pem_contents = f.read()
    
    # DER-decode the DER to get RSAPrivateKey DER structure, which is encoded as OCTETSTRING
    priv_der_contents = pem_to_der(priv_pem_contents)

    priv_der_contents = decoder.decode(priv_der_contents)[0][2]
    # DER-decode the octetstring (which is actually DER) and return (N, d)
    privkey = decoder.decode(priv_der_contents)

    return int(privkey[0][1]), int(privkey[0][3])

def pkcsv15pad_encrypt(plaintext, n):
    # calculate number of bytes required to represent the modulus N
    n_bytes = (n.bit_length() + 7) // 8

    # plaintext must be at least 11 bytes smaller than the modulus
    if len(plaintext) >= n_bytes - 11:
        raise ValueError("plaintext too long")
    
    # generate padding bytes
    ps_len = n_bytes - len(plaintext) - 3

    padding = b""
    while len(padding) < ps_len:
        random_byte = os.urandom(1)
        if random_byte != b"\x00":
            padding += random_byte
    padding = b"\x00\x02" + padding + b"\x00"

    
    # combine padding and plaintext
    padded_plaintext = padding + plaintext
    
    return padded_plaintext

def pkcsv15pad_sign(plaintext, n):
    # pad plaintext for signing according to PKCS#1 v1.5

    # calculate bytelength of modulus N
    n_bytes = (n.bit_length() + 7) // 8
    # plaintext must be at least 11 bytes smaller than the modulus N
    if len(plaintext) >= n_bytes - 11:
        raise ValueError("plaintext too long")
    
    # generate padding bytes
    ps_len = n_bytes - len(plaintext) - 3
    if ps_len < 8:
        ps_len = 9
    
    padding = b"\xff" * ps_len
    padding = b"\x00\x01" + padding + b"\x00"
    padded_plaintext = padding + plaintext
    
    return padded_plaintext

def pkcsv15pad_remove(plaintext):
    # removes PKCS#1 v1.5 padding

    i = 2
    while i < len(plaintext) and plaintext[i] != 0x00:
        i += 1
    i += 1

    # return the unpadded plaintext
    return plaintext[i:]

def encrypt(keyfile, plaintextfile, ciphertextfile):
    with open(plaintextfile, 'rb') as f:
        plaintext = f.read()
    N, e = get_pubkey(keyfile)
    padded_plaintext = pkcsv15pad_encrypt(plaintext, N)
    # convert padded_plaintext to integer
    padded_plaintext_int = bi(padded_plaintext)
    # encrypt padded_plaintext_int
    ciphertext_int = pow(padded_plaintext_int, e, N)
    # convert ciphertext_int to bytes
    ciphertext = ib(ciphertext_int)
    # write ciphertext to file
    with open(ciphertextfile, 'wb') as f:
        f.write(ciphertext)
    pass

def decrypt(keyfile, ciphertextfile, plaintextfile):
    with open(ciphertextfile, 'rb') as f:
        ciphertext = f.read()

    ciphertext_int = bi(ciphertext)
    N, d = get_privkey(keyfile)
    # decrypt ciphertext_int
    padded_plaintext_int = pow(ciphertext_int, d, N)

    # convert padded_plaintext_int to bytes
    padded_plaintext = ib(padded_plaintext_int)

    # remove padding
    plaintext = pkcsv15pad_remove(padded_plaintext)
    # write plaintext to file
    with open(plaintextfile, 'wb') as f:
        f.write(plaintext)
    pass

def digestinfo_der(filename):
    # returns ASN.1 DER encoded DigestInfo structure containing SHA256 digest of file
    with open(filename, 'rb') as f:
        file_contents = f.read()
    # calculate SHA256 digest of file_contents
    digest = hashlib.sha256(file_contents).digest()
    # asn1encode DigestInfo structure
    der = asn1_sequence(
            asn1_sequence(
                asn1_objectidentifier([2,16,840,1,101,3,4,2,1]) +  
                asn1_null()) + 
            asn1_octetstring(digest))
    return der

def sign(keyfile, filetosign, signaturefile):
    # construct plaintext 
    der = digestinfo_der(filetosign)
    # pad plaintext
    N, d = get_privkey(keyfile)
    padded_plaintext = pkcsv15pad_sign(der, N)
    # convert padded_plaintext to integer
    padded_int = bi(padded_plaintext)
    # calculate signature
    signature_int = pow(padded_int, d, N)
    # convert signature to bytes
    signature = ib(signature_int, length=(N.bit_length() + 7) // 8)
    # write signature to file
    with open(signaturefile, 'wb') as f:
        f.write(signature)
    pass

def verify(keyfile, signaturefile, filetoverify):
    # prints "Verified OK" or "Verification failure"
    # read signature from file
    with open(signaturefile, 'rb') as f:
        signature = f.read()
    # convert signature to integer
    signature_int = bi(signature)
    # calculate N and e from public key
    N, e = get_pubkey(keyfile)
    # calculate padded_plaintext_int
    padded_plaintext_int = pow(signature_int, e, N)
    # convert padded_plaintext_int to bytes
    padded_plaintext = ib(padded_plaintext_int)
    # remove padding
    plaintext = pkcsv15pad_remove(padded_plaintext)
    # construct plaintext
    der = digestinfo_der(filetoverify)
    # compare plaintext with signature
    if plaintext == der:
        print("Verified OK")
    else:
        print("Verification failure")
    pass
def usage():
    print("Usage:")
    print("encrypt <public key file> <plaintext file> <output ciphertext file>")
    print("decrypt <private key file> <ciphertext file> <output plaintext file>")
    print("sign <private key file> <file to sign> <signature output file>")
    print("verify <public key file> <signature file> <file to verify>")
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'encrypt':
    encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'decrypt':
    decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'sign':
    sign(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'verify':
    verify(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()