#!/usr/bin/env python3

import codecs, datetime, hashlib, re, sys, socket 
from urllib.parse import urlparse
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import namedtype, univ

# sudo apt install python3-pyasn1-modules
from pyasn1_modules import rfc2560, rfc5280


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

def asn1_octetstring(value_bytes):
    # octets - arbitrary byte string (e.g., b"abc\x01")
    # returns DER encoding of OCTETSTRING
    return bytes([0x04]) + asn1_len(value_bytes) + value_bytes

def asn1_sequence(der_bytes):
    # der - DER bytes to encapsulate into sequence
    # returns DER encoding of SEQUENCE
    return b'\x30' + asn1_len(der_bytes) + der_bytes

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

def asn1_null():
    # returns DER encoding of NULL
    return b'\x05\x00'

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
#==== ASN1 encoder end ====


def pem_to_der(content):
    # converts PEM-encoded X.509 certificate (if it is in PEM) to DER
    if content[:2] == b'--':
        content = content.replace(b"-----BEGIN CERTIFICATE-----", b"")
        content = content.replace(b"-----END CERTIFICATE-----", b"")
        content = codecs.decode(content, 'base64')
    return content

def get_name(cert):
    # gets subject DN from certificate
    name = encoder.encode(decoder.decode(cert, asn1Spec=rfc5280.Certificate())[0][0][5])
    return name

def get_key(cert):
    # gets subjectPublicKey from certificate
    subjectPublicKey = decoder.decode(cert)[0][0][6][1].asOctets()
    return subjectPublicKey

def get_serial(cert):
    # gets serial from certificate
    cert = decoder.decode(cert, asn1Spec=rfc5280.Certificate())[0][0]
    serial = cert[1]
    return serial
 
def get_ocsp_url(cert):
    # gets the OCSP responder's url from the certificate's AIA extension
    # pyasn1 syntax description to decode AIA extension
    class AccessDescription(univ.Sequence):
      componentType = namedtype.NamedTypes(
        namedtype.NamedType('accessMethod', univ.ObjectIdentifier()),
        namedtype.NamedType('accessLocation', rfc5280.GeneralName()))

    class AuthorityInfoAccessSyntax(univ.SequenceOf):
      componentType = AccessDescription()

    # looping over certificate extensions
    for seq in decoder.decode(cert)[0][0][7]:
        if str(seq[0])=='1.3.6.1.5.5.7.1.1': # look for AIA extension
            ext_value = bytes(seq[1])
            for aia in decoder.decode(ext_value, asn1Spec=AuthorityInfoAccessSyntax())[0]:
                if str(aia[0])=='1.3.6.1.5.5.7.48.1': # ocsp url
                    return str(aia[1].getComponentByName('uniformResourceIdentifier'))

    print("[-] OCSP url not found in the certificate!")
    exit(1)

def get_issuer_cert_url(cert):
    # gets the CA's certificate URL from the certificate's AIA extension (hint: see get_ocsp_url())
    

    # pyasn1 syntax description to decode AIA extension
    class AccessDescription(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType('accessMethod', univ.ObjectIdentifier()),
            namedtype.NamedType('accessLocation', rfc5280.GeneralName()))
        
    class AuthorityInfoAccessSyntax(univ.SequenceOf):
        componentType = AccessDescription()

    # looping over certificate extensions
    for seq in decoder.decode(cert)[0][0][7]:
        if str(seq[0])=='1.3.6.1.5.5.7.1.1': # look for AIA extension
            ext_value = bytes(seq[1])
            for aia in decoder.decode(ext_value, asn1Spec=AuthorityInfoAccessSyntax())[0]:
                if str(aia[0])=='1.3.6.1.5.5.7.48.2': # issuer certificate url
                    return str(aia[1].getComponentByName('uniformResourceIdentifier'))
    pass

def download_issuer_cert(issuer_cert_url):
    # downloads issuer certificate
    print("[+] Downloading issuer certificate from:", issuer_cert_url)

    # parse issuer certificate url
    url = urlparse(issuer_cert_url)
    host = url.netloc
    path = url.path

    # connect to host
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, 80))

    
    # send HTTP GET request
    s.send(b'GET ' + path.encode() + b' HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n')
    # read HTTP response header
    response_header = b""
    while True:
        response_header += s.recv(1)
        if response_header[-4:] == b'\r\n\r\n':
            break

    # get HTTP response length
    response_length = int(re.search('content-length:\s*(\d+)\s', response_header.decode(), re.S+re.I).group(1))

    # read HTTP response body
    response_body = b""
    while len(response_body) < response_length:
        response_body += s.recv(1)
    
    # ensure received byte length is equal to the length specified in the header
    
    if len(response_body) != response_length:
        print("[-] Received", len(response_body), "bytes (expected", response_length, "bytes)")
        print("[-] Error: HTTP response body length does not match the length specified in the header")
        print("[-] Exiting...")
        s.close()
        exit(1)

    issuer_cert = response_body

    # close connection
    s.close()
    
    return issuer_cert

def produce_request(cert, issuer_cert):
    # makes OCSP request in ASN.1 DER form

    issuer_name = get_name(issuer_cert)
    # SHA1 hash of issuer name
    issuer_name_hash = hashlib.sha1(issuer_name).digest()

    issuer_key = get_key(issuer_cert)
    
    # SHA1 hash of issuer public key
    issuer_key_hash = hashlib.sha1(issuer_key).digest()

    
    serial = get_serial(cert)


    print("[+] OCSP request for serial:", serial)
    
    request = asn1_sequence( # OCSPRequest
        asn1_sequence( # tbsRequest
            asn1_sequence( # requestList
                asn1_sequence( # reqCert
                    asn1_sequence( # certID
                        asn1_sequence( # hashAlgorithm
                            asn1_objectidentifier([1,3,14,3,2,26]) +  #sha1
                            asn1_null()
                        )+
                        asn1_octetstring(issuer_name_hash)+ # issuerNameHash
                        asn1_octetstring(issuer_key_hash)+ # issuerKeyHash
                        asn1_integer(int(serial)) # serialNumber
                    )))))
    
    return request

def send_req(ocsp_req, ocsp_url):
    # sends OCSP request to OCSP responder

    url = urlparse(ocsp_url)
    host = url.netloc

    # parse OCSP responder's url

    print("[+] Connecting to %s..." % (host))
    # connect to host

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, 80))

    # send HTTP POST request
    
    s.send(b'POST /' + b' HTTP/1.1\r\nHost: ' + host.encode() + b'\r\nContent-Type: application/ocsp-request\r\nContent-Length: ' + str(len(ocsp_req)).encode() + b'\r\n\r\n' + ocsp_req)

    # read HTTP response header

    response_header = b""
    while True:
        response_header += s.recv(1)
        if response_header[-4:] == b'\r\n\r\n':
            break

    # get HTTP response length

    response_length = int(re.search('content-length:\s*(\d+)\s', response_header.decode(), re.S+re.I).group(1))

    # read HTTP response body

    response_body = b""
    while len(response_body) < response_length:
        response_body += s.recv(1)
    
    # ensure received byte length is equal to the length specified in the header
    
    if len(response_body) != response_length:
        print("[-] Received", len(response_body), "bytes (expected", response_length, "bytes)")
        print("[-] Error: HTTP response body length does not match the length specified in the header")
        print("[-] Exiting...")
        s.close()
        exit(1)

    return response_body

def parse_ocsp_resp(ocsp_resp):
    # parses OCSP response
    ocspResponse, _ = decoder.decode(ocsp_resp, asn1Spec=rfc2560.OCSPResponse())
    responseStatus = ocspResponse.getComponentByName('responseStatus')
    assert responseStatus == rfc2560.OCSPResponseStatus('successful'), responseStatus.prettyPrint()
    responseBytes = ocspResponse.getComponentByName('responseBytes')
    responseType = responseBytes.getComponentByName('responseType')
    assert responseType == rfc2560.id_pkix_ocsp_basic, responseType.prettyPrint()

    response = responseBytes.getComponentByName('response')

    basicOCSPResponse, _ = decoder.decode(
        response, asn1Spec=rfc2560.BasicOCSPResponse()
    )

    tbsResponseData = basicOCSPResponse.getComponentByName('tbsResponseData')

    response0 = tbsResponseData.getComponentByName('responses').getComponentByPosition(0)

    producedAt = datetime.datetime.strptime(str(tbsResponseData.getComponentByName('producedAt')), '%Y%m%d%H%M%SZ')
    certID = response0.getComponentByName('certID')
    certStatus = response0.getComponentByName('certStatus').getName()
    thisUpdate = datetime.datetime.strptime(str(response0.getComponentByName('thisUpdate')), '%Y%m%d%H%M%SZ')
    nextUpdate = datetime.datetime.strptime(str(response0.getComponentByName('nextUpdate')), '%Y%m%d%H%M%SZ')

    # let's assume that the certID in the response matches the certID sent in the request

    # let's assume that the response is signed by a trusted responder

    print("[+] OCSP producedAt: %s +00:00" % producedAt)
    print("[+] OCSP thisUpdate: %s +00:00" % thisUpdate)
    print("[+] OCSP nextUpdate: %s +00:00" % nextUpdate)
    print("[+] OCSP status:", certStatus)

cert = pem_to_der(open(sys.argv[1], 'rb').read())

ocsp_url = get_ocsp_url(cert)
print("[+] URL of OCSP responder:", ocsp_url)

issuer_cert_url = get_issuer_cert_url(cert)

issuer_cert = download_issuer_cert(issuer_cert_url)

ocsp_req = produce_request(cert, issuer_cert)
ocsp_resp = send_req(ocsp_req, ocsp_url)
parse_ocsp_resp(ocsp_resp)
