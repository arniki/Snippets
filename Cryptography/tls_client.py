#!/usr/bin/env python3

import argparse, codecs, hmac, socket, sys, time, os, datetime
from hashlib import sha1, sha256
from Cryptodome.Cipher import ARC4
from pyasn1.codec.der import decoder 
from urllib.parse import urlparse



# parse arguments
parser = argparse.ArgumentParser(description='TLS v1.2 client')
parser.add_argument('url', type=str, help='URL to request')
parser.add_argument('--certificate', type=str, help='File to write PEM-encoded server certificate')
args = parser.parse_args()

def get_pubkey_certificate(cert):
    # reads the certificate and returns (n, e)
    
    # decode
    cert = decoder.decode(cert)[0]
    # get modulus and exponent
    cert =  decoder.decode(cert[0][6][1].asOctets())
    n = int(cert[0][0])
    e = int(cert[0][1])
    return (n, e)

def pkcsv15pad_encrypt(plaintext, n):
    # calculate number of bytes required to represent the modulus N
    n_bytes = (n.bit_length() + 7) // 8

    # plaintext must be at least 11 bytes smaller than the modulus
    if len(plaintext) > n_bytes - 11:
        raise ValueError("Plaintext too long")
    
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

def rsa_encrypt(cert, m):
    # encrypts message m using public key from certificate cert

    # get modulus and exponent
    (n, e) = get_pubkey_certificate(cert)

    # pad message
    padded_m = pkcsv15pad_encrypt(m, n)

    # encrypt
    c = pow(bi(padded_m), e, n)

    return ib(c)

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

# returns TLS record that contains ClientHello handshake message
def client_hello():
    global client_random,handshake_messages

    print("--> ClientHello()")

    # list of cipher suites the client supports
    # TLS_RSA_WITH_RC4_128_SHA
    csuite = b"\x00\x05"

    # add Handshake message header
    handshake_header = b"\x01" # ClientHello
    handshake_body = b"\x03\x03" # TLS version 1.2

    # randomness: first 4 bytes are current time in seconds, the rest is random
    client_random = ib(int(time.time()), 4) + os.urandom(28)
    handshake_body += client_random

    handshake_body += b"\x00" # session id length
    handshake_body += ib(len(csuite), 2) # cipher suites length
    handshake_body += csuite
    handshake_body += b"\x01" # compression methods length
    handshake_body += b"\x00" # compression method
    handshake_header += ib(len(handshake_body), 3) # handshake message length

    
    # add record layer header
    record_header = b"\x16" # content type: Handshake
    record_header += b"\x03\x03" # TLS version 1.2
    record_header += ib(len(handshake_header + handshake_body), 2) # length of message (excluding the record header)

    record = record_header + handshake_header + handshake_body

    handshake_messages += record[5:] # add handshake message to handshake_messages excluding TLS record layer header

    return record

# returns TLS record that contains ClientKeyExchange message containing encrypted pre-master secret
def client_key_exchange():
    global server_cert, premaster, handshake_messages

    print("--> ClientKeyExchange()")
    # generate pre-master secret
    premaster = os.urandom(46)
    premaster = b"\x03\x03" + premaster # TLS version 1.2

    # encrypt pre-master secret using RSA
    premaster = rsa_encrypt(server_cert, premaster)

    # add Handshake message header
    handshake_header = b"\x10" # ClientKeyExchange
    handshake_body = ib(len(premaster), 2) + premaster
    handshake_header += ib(len(handshake_body), 3) # handshake message length
    
    # add record layer header
    record_header = b"\x16" # content type: Handshake
    record_header += b"\x03\x03" # TLS version 1.2
    record_header += ib(len(handshake_header + handshake_body), 2) # length of message (excluding the record header)

    record = record_header + handshake_header + handshake_body

    handshake_messages += record[5:] # add handshake message to handshake_messages excluding TLS record layer header

    return record

# returns TLS record that contains ChangeCipherSpec message
def change_cipher_spec():
    print("--> ChangeCipherSpec()")
    global server_change_cipher_spec_received
    # add record layer header
    record_header = b"\x14" # content type: ChangeCipherSpec
    record_header += b"\x03\x03" # TLS version 1.2
    record_header += b"\x00\x01" # length of message (excluding the record header)
    record = record_header + b"\x01" # ChangeCipherSpec message
    return record

# returns TLS record that contains encrypted Finished handshake message
def finished():
    global handshake_messages, master_secret
    
    print("--> Finished()")
    client_verify = PRF(master_secret, b"client finished" + sha256(handshake_messages).digest(), 12)

    # add Handshake message header
    handshake_header = b"\x14" # Finished
    handshake_body = client_verify
    handshake_header += ib(len(handshake_body), 3) # handshake message length
    # add record layer header
    record_header = b"\x16" # content type: Handshake
    record_header += b"\x03\x03" # TLS version 1.2

    encrypted = encrypt(handshake_header + handshake_body, b"\x16", b"\x03\x03")

    # length of message (excluding the record header)
    record_header += ib(len(encrypted), 2)
    
    record = record_header + encrypted
    
    handshake_messages += record[5:]

    return record

# returns TLS record that contains encrypted Application data
def application_data(data):
    print("--> Application_data()")
    print(data.decode().strip())

    # add record layer header
    record_header = b"\x17" # content type: Application data
    record_header += b"\x03\x03" # TLS version 1.2
    encrypted = encrypt(data, b"\x17", b"\x03\x03")
    # length of message (excluding the record header)
    record_header += ib(len(encrypted), 2)
    record = record_header + encrypted
    
    return record

# parse TLS Handshake messages
def parsehandshake(r):
    global server_hello_done_received, server_random, server_cert, handshake_messages, server_change_cipher_spec_received, server_finished_received

    # decrypt if encryption enabled
    if server_change_cipher_spec_received:
        r = decrypt(r, b"\x16", b"\x03\x03")

    # read Handshake message type and length from message header
    htype, hlength = r[0:1], bi(r[1:4])

    body = r[4:4+hlength]
    handshake = r[:4+hlength]
    handshake_messages+= handshake

    if htype == b"\x02":
        print("	<--- ServerHello()")
        server_random = r[6:38]
        gmt = bi(server_random[0:4])
        gmt = datetime.datetime.utcfromtimestamp(gmt).strftime('%Y-%m-%d %H:%M:%S')
        sessidlen = bi(r[38:39])
        sessid = r[39:39+sessidlen]

        print("	[+] server randomness:", server_random.hex().upper())
        print("	[+] server timestamp:", gmt)
        print("	[+] TLS session ID:", sessid.hex().upper())

        cipher = r[39+sessidlen:41+sessidlen]

        if cipher==b"\x00\x2f":
            print("	[+] Cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA")
        elif cipher==b"\x00\x35":
            print("	[+] Cipher suite: TLS_RSA_WITH_AES_256_CBC_SHA")
        elif cipher==b"\x00\x05":
            print("	[+] Cipher suite: TLS_RSA_WITH_RC4_128_SHA")
        else:
            print("[-] Unsupported cipher suite selected:", cipher.hex())
            sys.exit(1)

        compression = r[41+sessidlen:42+sessidlen]

        if compression!=b"\x00":
            print("[-] Wrong compression:", compression.hex())
            sys.exit(1)
    elif htype == b"\x0b":
        print("	<--- Certificate()")
        
        # print first certificate length
        certlen = bi(r[7:10])
        
        print("	[+] Server certificate length:", certlen)
        server_cert = r[10:10+certlen]
        if args.certificate:
            
            cert = server_cert
            
            # convert DER to PEM
            cert = codecs.encode(cert, "base64")

            # add PEM header and footer
            cert = b"-----BEGIN CERTIFICATE-----\n" + cert + b"-----END CERTIFICATE-----\n"

            # write PEM-encoded certificate to file
            with open(args.certificate, "wb") as f:
                f.write(cert)
            
            print("	[+] Server certificate saved in:", args.certificate)
    elif htype == b"\x0e":
        print("	<--- ServerHelloDone()")
        server_hello_done_received = True



    elif htype == b"\x14":
        print("	<--- Finished()")
        # hashmac of all Handshake messages except the current Finished message (obviously)
        verify_data_calc = PRF(master_secret, b"server finished" + sha256(handshake_messages[:-4-hlength]).digest(), 12)
        server_verify = r[4:4+12]
        if server_verify!=verify_data_calc:
            print("[-] Server finished verification failed!")
            sys.exit(1)
    else:
        print("[-] Unknown Handshake Type:", htype.hex())
        sys.exit(1)

    # handle the case of several Handshake messages in one record
    leftover = r[4+len(body):]
    if len(leftover):
        parsehandshake(leftover)

# parses TLS record
def parserecord(r):
    global server_change_cipher_spec_received

    # parse TLS record header and pass the record body to the corresponding parsing method
    ctype = r[0:1]
    c = r[5:]

    # handle known types
    if ctype == b"\x16":
        print("<--- Handshake()")
        parsehandshake(c)
    elif ctype == b"\x14":
        print("<--- ChangeCipherSpec()")
        server_change_cipher_spec_received = True
    elif ctype == b"\x15":
        print("<--- Alert()")
        level, desc = c[0], c[1]
        if level == 1:
            print("	[-] warning:", desc)
        elif level == 2:
            print("	[-] fatal:", desc)
            sys.exit(1)
        else:
            sys.exit(1)
    elif ctype == b"\x17":
        print("<--- Application_data()")
        data = decrypt(c, b"\x17", b"\x03\x03")
        print(data.decode().strip())
    else:
        print("[-] Unknown TLS Record type:", ctype.hex())
        sys.exit(1)

# PRF defined in TLS v1.2
def PRF(secret, seed, l):

    out = b""
    A = hmac.new(secret, seed, sha256).digest()
    while len(out) < l:
        out += hmac.new(secret, A + seed, sha256).digest()
        A = hmac.new(secret, A, sha256).digest()
    return out[:l]

# derives master_secret
def derive_master_secret():
    global premaster, master_secret, client_random, server_random

    master_secret = PRF(premaster, b"master secret" + client_random + server_random, 48)
    
# derives keys for encryption and MAC
def derive_keys():
    global premaster, master_secret, client_random, server_random
    global client_mac_key, server_mac_key, client_enc_key, server_enc_key, rc4c, rc4s

    key_block = PRF(master_secret, b"key expansion" + server_random + client_random, 136)
    mac_size = 20
    key_size = 16
    iv_size = 16

    client_mac_key = key_block[:mac_size]
    server_mac_key = key_block[mac_size:mac_size*2]
    client_enc_key = key_block[mac_size*2:mac_size*2+key_size]
    server_enc_key = key_block[mac_size*2+key_size:mac_size*2+key_size*2]

    rc4c = ARC4.new(client_enc_key)
    rc4s = ARC4.new(server_enc_key)

# HMAC SHA1 wrapper
def HMAC_sha1(key, data):
    return hmac.new(key, data, sha1).digest()

# calculates MAC and encrypts plaintext
def encrypt(plain, type, version):
    global client_mac_key, client_enc_key, client_seq, rc4c

    mac = HMAC_sha1(client_mac_key, ib(client_seq, 8) + type + version + ib(len(plain), 2) + plain)
    ciphertext = rc4c.encrypt(plain + mac)
    client_seq+= 1
    return ciphertext

# decrypts ciphertext and verifies MAC
def decrypt(ciphertext, type, version):
    global server_mac_key, server_enc_key, server_seq, rc4s

    d = rc4s.decrypt(ciphertext)
    mac = d[-20:]
    plain = d[:-20]

    # verify MAC
    mac_calc = HMAC_sha1(server_mac_key, ib(server_seq, 8) + type + version + ib(len(plain), 2) + plain)
    if mac!=mac_calc:
        print("[-] MAC verification failed!")
        sys.exit(1)
    server_seq+= 1
    return plain

# read from the socket full TLS record
def readrecord():
    record = b""

    # read TLS record header (5 bytes)
    for _ in range(5):
        buf = s.recv(1)
        if not buf:
            print("[-] socket closed!")
            exit(1)
        record += buf

    # find data length
    datalen = bi(record[3:5])

    # read TLS record body
    for _ in range(datalen):
        buf = s.recv(1)
        if not buf:
            print("[-] socket closed!")
            exit(1)
        record += buf

    return record

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
url = urlparse(args.url)
host = url.netloc.split(':')
if len(host) > 1:
    port = int(host[1])
else:
    port = 443
host = host[0]


path = url.path

client_random = b""	# will hold client randomness
server_random = b""	# will hold server randomness
server_cert = b""	# will hold DER encoded server certificate
premaster = b""		# will hold 48 byte pre-master secret
master_secret = b""	# will hold master secret
handshake_messages = b"" # will hold concatenation of handshake messages

# client/server keys and sequence numbers
client_mac_key = b""
server_mac_key = b""
client_enc_key = b""
server_enc_key = b""
client_seq = 0
server_seq = 0

# client/server RC4 instances
rc4c = b""
rc4s = b""

s.connect((host, port))
s.send(client_hello())

server_hello_done_received = False
server_change_cipher_spec_received = False
server_finished_received = False

while not server_hello_done_received:
    parserecord(readrecord())

s.send(client_key_exchange())
s.send(change_cipher_spec())
derive_master_secret()
derive_keys()

s.send(finished())

print("client_mac_key:", client_mac_key.hex())
print("server_mac_key:", server_mac_key.hex())
print("client_enc_key:", client_enc_key.hex())
print("server_enc_key:", server_enc_key.hex())


while not server_finished_received:
    parserecord(readrecord())



s.send(application_data(b"GET / HTTP/1.0\r\n\r\n"))
parserecord(readrecord())

print("[+] Closing TCP connection!")
s.close()
