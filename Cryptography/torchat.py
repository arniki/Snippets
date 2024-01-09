#!/usr/bin/env python3

# sudo apt install python3-socks
import argparse
import socks
import socket
import sys
import secrets # https://docs.python.org/3/library/secrets.html

sserv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sserv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sserv.bind(('', 8888))
sserv.listen(0)

# parse arguments
parser = argparse.ArgumentParser(description='TorChat client')
parser.add_argument('--myself', required=True, type=str, help='My TorChat ID')
parser.add_argument('--peer', required=True, type=str, help='Peer\'s TorChat ID')
args = parser.parse_args()

# route outgoing connections through Tor
socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
socket.socket = socks.socksocket


# reads and returns torchat command from the socket
def read_torchat_cmd(incoming_socket):
    # read until newline
    data = b''
    while True:
        chunk = incoming_socket.recv(1)
        if not chunk:
            break
        data += chunk
        if b'\n' in data:
            break
    # return command
    print("[+] Received: %s" % data.strip().decode())
    return data.strip().decode()

# prints torchat command and sends it
def send_torchat_cmd(outgoing_socket, cmd):
    print("[+] Sending: %s" % cmd)
    outgoing_socket.sendall((cmd + '\n').encode())

# connecting to peer
print("[+] Connecting to %s" % args.peer)
outgoing_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
outgoing_socket.connect((args.peer + ".onion", 11009))

# sending ping

cookie = secrets.randbits(128)
ping_cmd = f'ping {args.myself} {cookie}'
send_torchat_cmd(outgoing_socket, ping_cmd)

# listening for the incoming connection

print("[+] Listening...")

(incoming_socket, address) = sserv.accept()

print("[+] Client %s:%s" % (address[0], address[1]))

# main loop for processing the received commands
incoming_authenticated = False
status_received = False
cookie_peer = ""
friend_added = False
while True:
    cmdr = read_torchat_cmd(incoming_socket)
    cmd = cmdr.split(' ')
    
    if cmd[0]=='ping':
        peer_torchat_id = cmd[1]
        cookie_peer = cmd[2]

    if cmd[0]=='pong':
        if cmd[1]==str(cookie):
            print("[+] Incoming connection authenticated!")
            incoming_authenticated = True
            pong_cmd = f'pong {cookie_peer}'
            send_torchat_cmd(outgoing_socket, pong_cmd)
        else:
            print("[+] Authentication failed!")
            break
    if cmd[0]=='status' and incoming_authenticated:
        status_received = True
        if cmd[1]=='available' and not friend_added:
            
            # sending add_me
            add_me_cmd = f'add_me'
            send_torchat_cmd(outgoing_socket, add_me_cmd)

            # sending status available
            status_available_cmd = f'status available'
            send_torchat_cmd(outgoing_socket, status_available_cmd)

            # sending profile name
            profile_name_cmd = f'profile_name Artur'
            send_torchat_cmd(outgoing_socket, profile_name_cmd)
            friend_added = True

    if cmd[0]=='message' and incoming_authenticated:
        # Get user input and send a message back
        message = input("[?] Enter message: ")
        
        message_cmd = f'message {message}'
        send_torchat_cmd(outgoing_socket, message_cmd)
            
        
