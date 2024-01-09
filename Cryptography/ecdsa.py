#!/usr/bin/env python3

import codecs, hashlib, os, sys 
from secp256r1 import curve
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
    for char in b:
        i <<= 8
        i |= char
    return i

# --------------- asn1 DER encoder
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
def asn1_sequence(der_bytes):
    # der - DER bytes to encapsulate into sequence
    # returns DER encoding of SEQUENCE
    return b'\x30' + asn1_len(der_bytes) + der_bytes
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
# --------------- asn1 DER encoder end


def pem_to_der(content):
    # converts PEM content (if it is PEM) to DER
    if content[:2] == b'--':
        content = content.replace(b"-----BEGIN PUBLIC KEY-----", b"")
        content = content.replace(b"-----END PUBLIC KEY-----", b"")
        content = content.replace(b"-----BEGIN PRIVATE KEY-----", b"")
        content = content.replace(b"-----END PRIVATE KEY-----", b"")
        content = codecs.decode(content, 'base64')
    return content

def get_privkey(filename):
    # reads EC private key file and returns the private key integer (d)
    privatekey = open(filename, 'rb').read()
    privatekey = pem_to_der(privatekey)
    privatekey = decoder.decode(privatekey)
    privatekey = decoder.decode(privatekey[0][2])
    d = bi(privatekey[0][1])
    return d

def get_pubkey(filename):
    # reads EC public key file and returns coordinates (x, y) of the public key point
    publickey = open(filename, 'rb').read()
    publickey = pem_to_der(publickey)
    publickey = decoder.decode(publickey)
    bitstring = publickey[0][1].asOctets()
    
    if len(bitstring) == 65:
        # uncompressed format
        x = bi(bitstring[1:33])
        y = bi(bitstring[33:])
    elif len(bitstring) == 33:
        # compressed format
        prefix = bitstring[:1]
        x = bi(bitstring[1:])
        y_squared = pow(x, 3, curve.p) + curve.b
        y = pow(y_squared, (curve.p + 1) // 4, curve.p)
        if (y % 2) != (prefix == b"\x03"):
            y = curve.p - y
    else:
        raise ValueError("Invalid public key format")
    return (x, y)

def ecdsa_sign(keyfile, filetosign, signaturefile):

    # get the private key
    d = get_privkey(keyfile)

    # calculate SHA-384 hash of the file to be signed
    h = hashlib.sha384(open(filetosign, 'rb').read()).digest()
    n = curve.n

    # truncate the hash value to the curve size
    h_int = bi(h)
    h_bits = h_int.bit_length()
    if h_bits > n.bit_length():
        h = h[:n.bit_length() // 8]
    else:
        h = b'\x00' * (n.bit_length() // 8 - h_bits // 8) + h

    # convert hash to integer
    z = bi(h)
    
    # generate a random nonce k in the range [1, n-1] using rejection sampling
    while True:
        k = bi(os.urandom(64)) % n 
        if k > 1 and k < (curve.n):
            break

    # calculate ECDSA signature components r and s
    s = 0
    r = 0
    while r == 0:
        R = curve.mul(curve.g, k)
        r = R[0] % n
        s = (pow(k,-1,n) * (z + r * d)) % curve.n

    # restart if s = 0 and pick a new nonce k
    if s == 0:
        ecdsa_sign(keyfile, filetosign, signaturefile)
    # DER-encode r and s
    r = asn1_integer(r)
    s = asn1_integer(s)

    # write DER structure to file
    der = asn1_sequence(r + s)
    open(signaturefile, 'wb').write(der)

def ecdsa_verify(keyfile, signaturefile, filetoverify):
    # prints "Verified OK" or "Verification failure"

    x, y = get_pubkey(keyfile)
    Q = (x, y)
    signature = open(signaturefile, 'rb').read()
    signature = pem_to_der(signature)
    signature = decoder.decode(signature)
    r = signature[0][0]
    s = signature[0][1]

    # calculate SHA-384 hash of the file to be verified
    h = hashlib.sha384(open(filetoverify, 'rb').read()).digest()
    n = curve.n

    # truncate the hash value to the curve size
    h_int = bi(h)
    h_bits = h_int.bit_length()
    if h_bits > n.bit_length():
        h = h[:n.bit_length() // 8]
    else:
        h = b'\x00' * (n.bit_length() // 8 - h_bits // 8) + h

    # convert hash to integer
    z = bi(h)

    # calculate R ′ = (h · s^−1 ) × G + (r · s^−1 ) × Q
    w = pow(s, -1, n)
    u1 = (z * w) % n
    u2 = (r * w) % n
    R = curve.add(curve.mul(curve.g, u1), curve.mul(Q, u2))

    # Verify r and s in [1, n − 1]
    if r < 1 or r > n - 1 or s < 1 or s > n - 1:
        print("Verification failure")
        return
    
    # Validate Q
    if not curve.valid(Q):
        print("Verification failure")
        return


    if R[0] == r:
        print("Verified OK")
    else:
        print("Verification failure")

def usage():
    print("Usage:")
    print("sign <private key file> <file to sign> <signature output file>")
    print("verify <public key file> <signature file> <file to verify>")
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'sign':
    ecdsa_sign(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'verify':
    ecdsa_verify(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()
