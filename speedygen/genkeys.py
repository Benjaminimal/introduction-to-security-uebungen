#!/usr/bin/python3

# Our efficient RSA key generation script. We sample the prime numbers from a file of precomputed primes
# instead of generating a new pair for each key.

import os
import random
import sys
from Crypto.PublicKey import RSA

# Iterative version of the extended GCD algorithm. Thx Wikipedia :)
def egcd(b, a):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while a != 0:
        q, b, a = b // a, a, b % a
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return  b, x0, y0

# Computes the inverse of a modulo m.
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

# Create a directory ignoring errors if it already exists.
def mkdir(name):
    try:
        os.mkdir(name, 0o755)
    except FileExistsError:
        pass

# Save the specified key to file.
def save(key, fname):
    with open(fname, 'wb') as f:
        f.write(key.exportKey())

def main(users_file):
    # Read the file with the primes.
    try:
        with open('primes.txt') as f:
            primes = [int(n) for n in f]
    except FileNotFoundError:
        sys.stderr.write('[!] Missing file with primes, aborting...')

    # Create folders for public and private keys.
    mkdir('pubkeys')
    mkdir('privkeys')

    moduli = []
    for user in users_file:
        # Ensure that we are not using the same modulus of another user. There should
        # be no problem in reusing just one prime (I think).
        ok = False
        while not ok:
            p, q = random.sample(primes, 2)
            n = p*q
            ok = n not in moduli
        moduli.append(n)

        # We use a fixed public exponent. Compute the private exponent and create a
        # RSA key out of it.
        e = 0x10001
        d = modinv(e, (p-1)*(q-1))
        key = RSA.construct((n, e, d))

        # Export the private and public components of the RSA key.
        save(key.publickey(), 'pubkeys/{}.pem'.format(user.strip()))
        save(key, 'privkeys/{}.pem'.format(user.strip()))

if __name__ == '__main__':
    try:
        with open(sys.argv[1]) as f:
            main(f)
    except (FileNotFoundError, IndexError):
        sys.stderr.write('[!] Missing or invalid users file.\n')
        sys.stderr.write('[*] Usage: python3 genkeys.py PATH_USERS_FILE\n')
        sys.exit(1)

