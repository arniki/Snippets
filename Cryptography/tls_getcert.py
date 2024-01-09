#!/usr/bin/env python3

import argparse, codecs, datetime, os, socket, sys, time 
from urllib.parse import urlparse



# parse arguments
parser = argparse.ArgumentParser(description='TLS v1.2 client')
parser.add_argument('url', type=str, help='URL to request')
parser.add_argument('--certificate', type=str, help='File to write PEM-encoded server certificate')
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

# returns TLS record that contains ClientHello Handshake message
def client_hello():

    print("--> ClientHello()")

    # list of cipher suites the client supports
    csuite = b"\x00\x05" # TLS_RSA_WITH_RC4_128_SHA
    csuite += b"\x00\x2f" # TLS_RSA_WITH_AES_128_CBC_SHA
    csuite += b"\x00\x35" # TLS_RSA_WITH_AES_256_CBC_SHA


    # add Handshake message header
    handshake_header = b"\x01" # ClientHello
    handshake_body = b"\x03\x03" # TLS version 1.2

    # randomness: first 4 bytes are current time in seconds, the rest is random
    handshake_body += ib(int(time.time()), 4) + os.urandom(28)

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
    return record

# returns TLS record that contains 'Certificate unknown' fatal Alert message
def alert():
    print("--> Alert()")

    # add alert message
    alert_header = b"\x02" # fatal
    alert_header += b"\x2e" # handshake failure
    
    # add record layer header
    record_header = b"\x15" # content type: Alert
    record_header += b"\x03\x03" # TLS version 1.2
    record_header += ib(len(alert_header), 2) # length of message (excluding the record header)

    record = record_header + alert_header

    return  record

# parse TLS Handshake messages
def parsehandshake(r):
    global server_hello_done_received

    # read Handshake message type and length from message header
    htype = r[0:1]
    
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
        if args.certificate:
            
            cert = r[10:10+certlen]
            
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
    
    else:
        print("[-] Unknown Handshake type:", htype.hex())
        sys.exit(1)

    # handle the case of several Handshake messages in one record
    leftover = r[bi(r[1:4])+4:]
    if len(leftover):
        parsehandshake(leftover)

# parses TLS record
def parserecord(r):
    # parse TLS record header and pass the record body to the corresponding parsing method (i.e., parsehandshake())
    print("<-- Handshake()")
    parsehandshake(r)
    
    return

# read from the socket full TLS record
def readrecord():
    global s

    record = b""
    header = b""
    # read the TLS record header (5 bytes)
    while len(header) < 5:
        data = s.recv(1)
        if not data:
            print("[-] Connection closed")
            exit(1)
        header += data

    # find data length
    data_length = bi(header[3:5])
    
    # read the TLS record body
    while len(record) < data_length:
        data = s.recv(1)
        if not data:
            print("[-] Connection closed")
            exit(1)
        record += data

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

s.connect((host, port))

s.send(client_hello())

server_hello_done_received = False
while not server_hello_done_received:
    parserecord(readrecord())
s.send(alert())

print("[+] Closing TCP connection!")
s.close()
