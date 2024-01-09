#!/usr/bin/env python3

import hmac 
import hashlib
import sys
from pyasn1.codec.der import decoder
# don't remove! otherwise the library import below will try to import hmac.py file 
sys.path = sys.path[1:]



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
    # der - DER encoded bytestring
    # tag - tag value to specify in the type octet
    # returns DER encoding of original DER that is encapsulated in tag type

    tag_byte = 0xa0 | (tag & 0x1f)

    return bytes([tag_byte]) + asn1_len(der) + der
# ==== ASN1 encoder end ====


def mac(filename):
    key = input("[?] Enter key: ").encode()

    hmac_object = hmac.new(key, None, hashlib.sha256)
    with open(filename, 'rb') as f:
        while True:
            chunk = f.read(512)
            if not chunk:
                break
            hmac_object.update(chunk)

    hmac_digest = hmac_object.digest()

    encoded_digest_info = asn1_sequence(asn1_sequence(asn1_objectidentifier([2,16,840,1,101,3,4,2,1]) + asn1_null()) + asn1_octetstring(hmac_digest))

    with open(filename+".hmac", 'wb') as f:
        f.write(encoded_digest_info)

    print("[+] Calculated HMAC-SHA256:", hmac_digest.hex())
    print("[+] Writing HMAC DigestInfo to", filename+".hmac")


def verify(filename):
    print("[+] Reading HMAC DigestInfo from", filename+".hmac")

    hmac_digest = open(filename + '.hmac', 'rb').read()
    der_encoded_digest_info = decoder.decode(hmac_digest)

    digest_algorithm_oid = der_encoded_digest_info[0][0][0]
    digest_hmac = der_encoded_digest_info[0][1]

    if str(digest_algorithm_oid) == '1.2.840.113549.2.5':
        digest_algorithm = hashlib.md5
    elif str(digest_algorithm_oid) == '1.3.14.3.2.26':
        digest_algorithm = hashlib.sha1
    elif str(digest_algorithm_oid) == '2.16.840.1.101.3.4.2.1':
        digest_algorithm = hashlib.sha256
    else:
        raise ValueError(
            f"Unsupported digest algorithm OID: {digest_algorithm_oid}")
    
    if digest_algorithm == hashlib.sha256:
        print("[+] HMAC-SHA256 digest:", bytes(digest_hmac).hex())

    if digest_algorithm == hashlib.sha1:
        print("[+] HMAC-SHA1 digest:", bytes(digest_hmac).hex())

    if digest_algorithm == hashlib.md5:
        print("[+] HMAC-MD5 digest:", bytes(digest_hmac).hex())

    key = input("[?] Enter key: ").encode()

    digest_calculated = hmac.new(key, None, digest_algorithm)

    with open(filename, 'rb') as f:
        while True:
            chunk = f.read(512)
            if not chunk:
                break
            digest_calculated.update(chunk)

    hmac_digest_calculated = digest_calculated.digest()

    if digest_algorithm == hashlib.sha256:
        print("[+] Calculated HMAC-SHA256:", hmac_digest_calculated.hex())

    if digest_algorithm == hashlib.sha1:
        print("[+] Calculated HMAC-SHA1:", hmac_digest_calculated.hex())

    if digest_algorithm == hashlib.md5:
        print("[+] Calculated HMAC-MD5:", hmac_digest_calculated.hex())

    if hmac_digest_calculated != digest_hmac:
        print("[-] Wrong key or message has been manipulated!")
    else:
        print("[+] HMAC verification successful!")


def usage():
    print("Usage:")
    print("-mac <filename>")
    print("-verify <filename>")
    sys.exit(1)


if len(sys.argv) != 3:
    usage()
elif sys.argv[1] == '-mac':
    mac(sys.argv[2])
elif sys.argv[1] == '-verify':
    verify(sys.argv[2])
else:
    usage()