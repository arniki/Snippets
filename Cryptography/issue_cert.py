#!/usr/bin/env python3

import argparse, codecs, hashlib, os, sys 
from pyasn1.codec.der import decoder, encoder


# parse arguments
parser = argparse.ArgumentParser(description='issue TLS server certificate based on CSR', add_help=False)
parser.add_argument("CA_cert_file", help="CA certificate (in PEM or DER form)")
parser.add_argument("CA_private_key_file", help="CA private key (in PEM or DER form)")
parser.add_argument("csr_file", help="CSR file (in PEM or DER form)")
parser.add_argument("output_cert_file", help="File to store certificate (in PEM form)")
args = parser.parse_args()

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
# put your DER encoder functions here
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

def asn1_sequence(der_bytes):
    # der - DER bytes to encapsulate into sequence
    # returns DER encoding of SEQUENCE
    return b'\x30' + asn1_len(der_bytes) + der_bytes

def asn1_octetstring(value_bytes):
    # octets - arbitrary byte string (e.g., b"abc\x01")
    # returns DER encoding of OCTETSTRING
    return bytes([0x04]) + asn1_len(value_bytes) + value_bytes

def asn1_boolean(boolean):
    # BOOLEAN encoder has been implemented for you
    if boolean:
        boolean = b'\xff'
    else:
        boolean = b'\x00'
    return bytes([0x01]) + asn1_len(boolean) + boolean

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

def asn1_utf8string(utf8_bytes):
    # utf8bytes - bytes containing UTF-8 encoded unicode characters (e.g., b"F\xc5\x8d\xc5\x8d")
    # returns DER encoding of UTF8String
    return b'\x0c' + asn1_len(utf8_bytes) + utf8_bytes

def asn1_set(der_bytes):
    # der - DER bytes to encapsulate into set
    # returns DER encoding of SET
    return b'\x31' + asn1_len(der_bytes) + der_bytes

def asn1_utctime(time):
    # time - bytes containing timestamp in UTCTime format (e.g., b"121229010100Z")
    # returns DER encoding of UTCTime
    return b'\x17' + asn1_len(time) + time

def asn1_bitstring(bitstr):
    # bitstr - string containing bitstring (e.g., "10101")
    # returns DER encoding of BITSTRING
    num_padding_bits = 8 - (len(bitstr) % 8)
    if num_padding_bits == 8:
        num_padding_bits = 0

    value_bytes = []
    byte_value = 0
    bit_count = 0
    for bit in bitstr:
        if bit == '1':
            byte_value |= 1 << (7 - bit_count)
        bit_count += 1
        if bit_count == 8:
            value_bytes.append(byte_value)
            byte_value = 0
            bit_count = 0
    if bit_count != 0:
        value_bytes.append(byte_value)

    return b'\x03' + asn1_len(bytes(value_bytes) + bytes([num_padding_bits])) + bytes([num_padding_bits]) + bytes(value_bytes)

def asn1_tag_explicit(der, tag):
    # der - DER encoded bytestring
    # tag - tag value to specify in the type octet
    # returns DER encoding of original DER that is encapsulated in tag type

    tag_byte = 0xa0 | (tag & 0x1f)

    return bytes([tag_byte]) + asn1_len(der) + der

def asn1_bitstring_der(bitstring):
    # prepend a 0 byte to the bitstring
    bitstring = b'\x00' + bitstring
    # calculate the length octet(s) for the encapsulated bitstring field
    length_octets = asn1_len(bitstring)
    # prepend the length octet(s) to the bitstring
    bitstring = length_octets + bitstring
    # prepend the type byte (0x03 for BIT STRING)
    bitstring = b'\x03' + bitstring
    # return the result as an encapsulated bitstring field
    return bitstring

#==== ASN1 encoder end ====

def pem_to_der(content):
    # converts PEM content (if it is PEM) to DER
    if content[:2] == b'--':
        content = content.replace(b"-----BEGIN CERTIFICATE REQUEST-----", b"")
        content = content.replace(b"-----END CERTIFICATE REQUEST-----", b"")
        content = content.replace(b"-----BEGIN CERTIFICATE-----", b"")
        content = content.replace(b"-----END CERTIFICATE-----", b"")
        content = content.replace(b"-----BEGIN PUBLIC KEY-----", b"")
        content = content.replace(b"-----END PUBLIC KEY-----", b"")
        content = content.replace(b"-----BEGIN PRIVATE KEY-----", b"")
        content = content.replace(b"-----END PRIVATE KEY-----", b"")
        content = codecs.decode(content, 'base64')
    return content

def get_privkey(filename):
    # reads RSA private key file and returns (n, d)
    privkey = pem_to_der(open(filename, 'rb').read())
    privkey = decoder.decode(privkey)
    privkey = decoder.decode(privkey[0][2])

    return int(privkey[0][1]), int(privkey[0][3])

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

def digestinfo_der(m):
    # returns ASN.1 DER encoded DigestInfo structure containing SHA256 digest of file
    # calculate SHA256 digest of file_contents
    digest = hashlib.sha256(m).digest()
    # asn1encode DigestInfo structure
    der = asn1_sequence(
            asn1_sequence(
                asn1_objectidentifier([1,2,840,113549,1,1,11]) +  
                asn1_null()) + 
            asn1_octetstring(digest))
    return der

def sign(m, keyfile):
    # signs DigestInfo of message m
    digestinfo = digestinfo_der(m)

    # read private key from file
    N, d = get_privkey(keyfile)

    # pad digestinfo for signing
    padded_digestinfo = pkcsv15pad_sign(digestinfo, N)

    # convert padded digestinfo to integer
    padded_digestinfo_int = bi(padded_digestinfo)

    # sign padded digestinfo
    signature = pow(padded_digestinfo_int, d, N)

    # convert signature to bytes
    signature = ib(signature, length=(N.bit_length() + 7) // 8)

    
    return signature

def get_subject_cn(csr_der):
    # returns CommonName value from CSR's Distinguished Name field
    csr = decoder.decode(csr_der)
    csr = csr[0][0]

    #  looping over Distinguished Name entries until CN found (2 5 4 3)
    for i in range(1, len(csr)):
        if type(csr[i]) == int:
            break
        for j in range(len(csr[i])):
            if type(csr[i][j]) == int:
                break
            for k in range(len(csr[i][j])):
                if type(csr[i][j][k]) == int:
                    break
                for l in range(len(csr[i][j][k])):
                    if type(csr[i][j][k][l]) == int:
                        break
                    if str(csr[i][j][k][l]) == '2.5.4.3':
                        cn_str = str(csr[i][j][k][l+1])
                        break

    return cn_str

def get_subjectPublicKeyInfo(csr_der):
    # returns DER-encoded subjectPublicKeyInfo from CSR
    return encoder.encode(decoder.decode(csr_der)[0][0][2])

def get_subjectName(cert_der):
    # returns DER-encoded subject name from CA certificate
    return encoder.encode(decoder.decode(cert_der)[0][0][5])

def issue_certificate(private_key_file, issuer, subject, pubkey):
    # receives CA private key filename, DER-encoded CA Distinguished Name, self-constructed DER-encoded subject's Distinguished Name and DER-encoded subjectPublicKeyInfo
    # returns X.509v3 certificate in PEM format
    
    # create certificate
    der = asn1_sequence(                                # tbsCertificate
                asn1_tag_explicit(asn1_integer(2), 0) + # version
                asn1_integer(4138208570) +              # serialNumber
                asn1_sequence(                          # signature
                    asn1_objectidentifier([1,2,840,113549,1,1,11]) + # sha256WithRSAEncryption
                    asn1_null()) +
                issuer +                    # issuer
                asn1_sequence(              # validity
                    asn1_utctime(b"230101000000Z") +  # notBefore
                    asn1_utctime(b"240101000000Z")) + # notAfter 
                subject +                             # subject
                pubkey +                              # subjectPublicKeyInfo
                asn1_tag_explicit(asn1_sequence(      # Extensions 
                    
                    # basicConstraints Extension
                    asn1_sequence(          
                        asn1_objectidentifier([2,5,29,19]) + # basicConstraints OID
                        asn1_boolean(True) + # critical TRUE
                        asn1_octetstring(asn1_sequence(asn1_boolean(False) ))) + # CA FALSE
                    
                    # keyUsage Extension
                    asn1_sequence(          
                        asn1_objectidentifier([2,5,29,15]) +    # keyUsage OID
                        asn1_boolean(True) +                    # critical TRUE
                        asn1_octetstring(asn1_bitstring('1'))) + # digitalSignature

                    # extendedKeyUsage Extension
                    asn1_sequence(          
                        asn1_objectidentifier([2,5,29,37]) +    # extendedKeyUsage OID
                        asn1_boolean(True) +                    # critical TRUE
                        asn1_octetstring(asn1_sequence(asn1_objectidentifier([1,3,6,1,5,5,7,3,1]))) # id-kp-serverAuth
                    )),3)) 
                               
    # sign certificate
    signature = sign(der, private_key_file)

    
    # convert signature bytes to binary string
    signature = bin(bi(signature))[2:]
    
    
    # append signature to certificate
    der = asn1_sequence(der + 
                        asn1_sequence(
                            asn1_objectidentifier([1,2,840,113549,1,1,11]) + 
                            asn1_null()) + 
                            asn1_bitstring(signature))

    # convert certificate to PEM format
    pem = b'-----BEGIN CERTIFICATE-----\n' + codecs.encode(der, 'base64') + b'-----END CERTIFICATE-----\n'

    return pem


# obtain subject's CN from CSR
csr_der = pem_to_der(open(args.csr_file, 'rb').read())
subject_cn_text = get_subject_cn(csr_der)

print("[+] Issuing certificate for \"%s\"" % (subject_cn_text))

# obtain subjectPublicKeyInfo from CSR
pubkey = get_subjectPublicKeyInfo(csr_der)

# construct subject name DN for end-entity's certificate
subject = asn1_sequence(asn1_set(asn1_sequence(asn1_objectidentifier([2, 5, 4, 3]) + asn1_utf8string(bytes(subject_cn_text, 'utf-8')))))
        

# get subject name DN from CA certificate
CAcert = pem_to_der(open(args.CA_cert_file, 'rb').read())
CAsubject = get_subjectName(CAcert)

# issue certificate
cert_pem = issue_certificate(args.CA_private_key_file, CAsubject, subject, pubkey)
open(args.output_cert_file, 'wb').write(cert_pem)
