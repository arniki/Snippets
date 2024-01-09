#!/usr/bin/env python3

import argparse
import hashlib
import sys
import datetime



## Output of running `pow.py --difficulty 26`:
## identity = 'Artur'
## [+] Solved in 206.345431 sec (0.5589 Mhash/sec)
## [+] Input: 41727475720000000006df96d4
## [+] Solution: 0000000b2be917fd9eff0a1c632fca1935cead1c3d571e435f43899f046926b5
## [+] Nonce: 115316436
##
##
## identity = 'Artur Nikitchuk'
## [+] Solved in 83.996380 sec (0.5452 Mhash/sec)
## [+] Input: 4172747572204e696b69746368756b204170706c6965642043727970746f20486f6d65776f726b2031350000000002bac00d
## [+] Solution: 000000023c4db03be5a66c85901cdd1a71c11287a3a48db1749dcf22fb346253
## [+] Nonce: 45793293

# Calculate the double SHA256 hash of the input data
def calculate_hash(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# Perform the proof-of-work calculation
def solve_proof_of_work(difficulty, identity):
    counter = 0
    start_time = datetime.datetime.now()

    while True:
        nonce = counter.to_bytes(8, 'big')
        data = identity.encode() + nonce
        hash_result = calculate_hash(data)
        leading_zeros = count_leading_zeros(hash_result)
        if leading_zeros >= difficulty:
            end_time = datetime.datetime.now()
            elapsed_time = (end_time - start_time).total_seconds()
            hash_rate = counter / elapsed_time / 1000000  # Mhash/sec
            return nonce, hash_result, elapsed_time, hash_rate

        counter += 1

def count_leading_zeros(byte_array):
    count = 0
    for byte in byte_array:
        if byte == 0:
            count += 8 
        else:
            mask = 0x80  
            while byte & mask == 0:
                count += 1
                byte <<= 1 
            return count


# Parse arguments
parser = argparse.ArgumentParser(description='Proof-of-work solver')
parser.add_argument('--difficulty', default=0, type=int, help='Number of leading zero bits')
args = parser.parse_args()

# Solve the proof-of-work problem
identity = 'Artur'
nonce, solution, elapsed_time, hash_rate = solve_proof_of_work(args.difficulty, identity)

# Print the results
print("[+] Solved in {:.6f} sec ({:.4f} Mhash/sec)".format(elapsed_time, hash_rate))
print("[+] Input:", identity.encode().hex() + nonce.hex())
print("[+] Solution:", solution.hex())
print("[+] Nonce:", int.from_bytes(nonce, 'big'))