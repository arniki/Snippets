#!/usr/bin/env python3


import codecs
import datetime
import hashlib
import io
import sys
import zipfile

# apt-get install python3-bs4 python3-pyasn1-modules python3-m2crypto python3-lxml
import M2Crypto
import lxml.etree
from bs4 import BeautifulSoup
from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc2560



def verify_ecdsa(cert, signature_value, signed_hash):
    # verifies ECDSA signature given the hash value
    X509 = M2Crypto.X509.load_cert_der_string(cert)
    EC_pubkey = M2Crypto.EC.pub_key_from_der(X509.get_pubkey().as_der())

    # constructing r and s to satisfy M2Crypto
    l = len(signature_value)//2
    r = signature_value[:l]
    s = signature_value[l:]
    if r[0]>>7:
        r = b'\x00' + r
    if s[0]>>7:
        s = b'\x00' + s
    r = b'\x00\x00\x00' + bytes([len(r)]) + r
    s = b'\x00\x00\x00' + bytes([len(s)]) + s
    return EC_pubkey.verify_dsa(signed_hash, r, s)

def parse_tsa_response(timestamp_resp):
    # extracts from a TSA response the timestamp and timestamped DigestInfo
    timestamp = decoder.decode(timestamp_resp)
    tsinfo = decoder.decode(timestamp[0][1][2][1])[0]
    ts_digestinfo = encoder.encode(tsinfo[2])
    ts = datetime.datetime.strptime(str(tsinfo[4]), '%Y%m%d%H%M%SZ')
    # let's assume that the timestamp has been issued by a trusted TSA
    return ts, ts_digestinfo

def parse_ocsp_response(ocsp_resp):
    # extracts from an OCSP response certID_serial, certStatus and thisUpdate
    ocspResponse, _ = decoder.decode(ocsp_resp, asn1Spec=rfc2560.OCSPResponse())
    responseStatus = ocspResponse.getComponentByName('responseStatus')
    assert responseStatus == rfc2560.OCSPResponseStatus('successful'), responseStatus.prettyPrint()
    responseBytes = ocspResponse.getComponentByName('responseBytes')
    responseType = responseBytes.getComponentByName('responseType')
    assert responseType == rfc2560.id_pkix_ocsp_basic, responseType.prettyPrint()
    response = responseBytes.getComponentByName('response')
    basicOCSPResponse, _ = decoder.decode(response, asn1Spec=rfc2560.BasicOCSPResponse())
    tbsResponseData = basicOCSPResponse.getComponentByName('tbsResponseData')
    response0 = tbsResponseData.getComponentByName('responses').getComponentByPosition(0)
    # TODO implement checks for untrusted OCSP responders
    certID = response0.getComponentByName('certID')
    # TODO implement checks for issuer name and key hashes in certID 
    certID_serial = certID[3]
    certStatus = response0.getComponentByName('certStatus').getName()
    thisUpdate = datetime.datetime.strptime(str(response0.getComponentByName('thisUpdate')), '%Y%m%d%H%M%SZ')

    return certID_serial, certStatus, thisUpdate

def canonicalize(full_xml, tagname):
    # returns XML canonicalization of an element with the specified tagname
    if type(full_xml)!=bytes:
        print("[-] canonicalize(): input is not a bytes object containing XML:", type(full_xml))
        exit(1)
    input = io.BytesIO(full_xml)
    et = lxml.etree.parse(input)
    output = io.BytesIO()
    lxml.etree.ElementTree(et.find('.//{*}'+tagname)).write_c14n(output)
    return output.getvalue()

def get_subject_cn(cert_der):
    # returns CommonName value from the certificate's Subject Distinguished Name field
    # looping over Distinguished Name entries until CN found
    for rdn in decoder.decode(cert_der)[0][0][5]:
        if str(rdn[0][0]) == '2.5.4.3': # CommonName
            return str(rdn[0][1])
    return ''

filename = sys.argv[1]

# get and decode XML
with zipfile.ZipFile(filename, 'r') as z:
    xml = z.read('META-INF/signatures0.xml')
xmldoc = BeautifulSoup(xml, features='xml')




signers_cert_der = codecs.decode(xmldoc.XAdESSignatures.KeyInfo.X509Data.X509Certificate.encode_contents(), 'base64')
print("[+] Signatory:", get_subject_cn(signers_cert_der))

# Get signed file name
signed_file = xmldoc.XAdESSignatures.Signature.SignedInfo.Reference['URI']
print("[+] Signed file:", signed_file)


# Check if certificate hash included in the signature is correct
cert_hash = xmldoc.XAdESSignatures.Signature.Object.QualifyingProperties.SignedProperties.SignedSignatureProperties.SigningCertificate.Cert.CertDigest.DigestValue.encode_contents()
if hashlib.sha256(signers_cert_der).digest() != codecs.decode(cert_hash, 'base64'):
    print("[-] Signing certificate digest does not match.")
    exit(1)


# Check document hash that resides in the root directory of the archive
with zipfile.ZipFile(filename, 'r') as z:
    file = z.read(signed_file)

signed_file_hash =  hashlib.sha256(file).digest()
signed_file_hash_reference = xmldoc.XAdESSignatures.Signature.SignedInfo.Reference.DigestValue.encode_contents()
if signed_file_hash != codecs.decode(signed_file_hash_reference, 'base64'):
    print("[-] Signed file hash does not match.")
    exit(1)


# Check hash of SignedProperties element matches the digest in the signature
signed_properties_reference = xmldoc.XAdESSignatures.Signature.SignedInfo.find('Reference',attrs={'URI':'#S0-SignedProperties'}).DigestValue.encode_contents()
signed_properties = canonicalize(xml, 'SignedProperties')

if hashlib.sha256(signed_properties).digest() != codecs.decode(signed_properties_reference, 'base64'):
    print("[-] SignedProperties digest does not match.")
    exit(1)


# Check for signing after OCSP timestamp 
# Get OCSP timestamp
ocsp_resp = xmldoc.XAdESSignatures.Signature.Object.UnsignedProperties.UnsignedSignatureProperties.RevocationValues.OCSPValues.EncapsulatedOCSPValue.encode_contents()
ocsp_resp = codecs.decode(ocsp_resp, 'base64')
certID_serial, certStatus, thisUpdate = parse_ocsp_response(ocsp_resp)

# Timestamp
ts = xmldoc.XAdESSignatures.Signature.Object.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties.SignatureTimeStamp.EncapsulatedTimeStamp.encode_contents()
ts = codecs.decode(ts, 'base64')
ts, ts_digestinfo = parse_tsa_response(ts)

# check if OCSP timestamp is before or after signing time
if ts > thisUpdate:
    print("[-] OCSP timestamp is before signing time.")
    exit(1)

signature_value = codecs.decode(xmldoc.XAdESSignatures.Signature.SignatureValue.encode_contents(), 'base64')
signed_info_str = canonicalize(xml, 'SignedInfo')


# Check if certificate serial number matches the one in the OCSP response
X509SerialNumber = signed_properties_reference = xmldoc.XAdESSignatures.Signature.Object.find('SignedProperties',attrs={'Id':'S0-SignedProperties'}).X509SerialNumber.encode_contents()

if str(X509SerialNumber.decode('utf-8')) != str(certID_serial):
    print("[-] Certificate serial number does not match the one in the OCSP response.")
    exit(1)

# Check OCSP status
if certStatus != 'good':
    print("[-] OCSP certificate is revoked.")
    exit(1)

# Check TSA response validity
# get TSA response
EncapsulatedTimeStamp = signed_properties_reference = xmldoc.XAdESSignatures.Signature.Object.find('EncapsulatedTimeStamp').encode_contents()
EncapsulatedTimeStamp = codecs.decode(EncapsulatedTimeStamp, 'base64')

# get SignatureValue bytes
canon_signaturevalue = canonicalize(xml, 'SignatureValue')
canon_signaturevalue = hashlib.sha256(canon_signaturevalue).digest()

# get SignatureValue octetstring within TSA response
tsa_response_digest = decoder.decode(decoder.decode(EncapsulatedTimeStamp)[0][1][2][1])[0][2][1].asOctets()

if tsa_response_digest != canon_signaturevalue:
    print("[-] SignatureValue does not match TSA response digest.")
    exit(1)
print("[+] Timestamped: %s +00:00" % (ts))
# finally verify signatory's signature
if verify_ecdsa(signers_cert_der, signature_value, hashlib.sha384(signed_info_str).digest()):
    print("[+] Signature verification successful!")
else:
    print("[-] Signature verification failed!")
