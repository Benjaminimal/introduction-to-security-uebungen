speedygen
==============

Overview
--------
The program in question is a keygen for RSA keys. It's supposed to be incredibly fast while not being less safe than others. As a challenge we were provided with the source code and a set of public keys and an encrypted message for each of those in order to prove the creators of this keygen wrong by decrypting those messages.

Vulnerability
-------------
This keygen can sometimes reuse primes for different keys since it reads primes from a stored file and when generating keys only makes sure that the same modulo is not used more than once. When this happens the tow created moduli share a divisor which can easily be retrieved through the euclidian algorithm which enables us the get the other factors and reconstruct the secret keys.

Exploitation
------------
In order to solve this challenge I created a python script to load all the public keys, search through the pairs for shared prime factors and save the private key from that.

    #!/usr/bin/env python3
    import os

    from Crypto.PublicKey import RSA

    PUB_KEY_DIR = 'pubkeys'
    PUB_KEY_EXTENSION = '.pem'


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


    def pair_zip(lst):
        pairs = []
        for i, x in enumerate(lst):
            for j in range(i, len(lst)):
                y = lst[j]
                if x != y:
                    pairs.append((x, y))
        return pairs


    def main():
        mkdir('privkeys')

        keys = []
        for file_name in os.listdir(PUB_KEY_DIR):
            with open(os.path.join(PUB_KEY_DIR, file_name), 'r') as f:
                content = f.read()
                key = RSA.importKey(content)
                keys.append(
                    {
                        "name": file_name.replace(PUB_KEY_EXTENSION, ""),
                        "key": key,
                    }
                )

        pairs = pair_zip(keys)

        for (x, y) in pairs:
            p, _, _ = egcd(x["key"].n, y["key"].n)
            if p > 1:
                q = x["key"].n // p
                d = modinv(x["key"].e, (p-1) * (q-1))
                key = RSA.construct((x["key"].n, x["key"].e, d))
                save(key, 'privkeys/{}.pem'.format(x["name"]))


    if __name__ == '__main__':
        main()

Additionally I copied and modified the provided bash script `encrypt.sh` to decrypt the messages with the newly generated private keys.

    #!/bin/bash

    ENCFOLDER='messages'
    PLAINFOLDER='messages'
    KEYFOLDER='privkeys'

    [ -d "${PLAINFOLDER}" ] || mkdir "${PLAINFOLDER}"

    for key in $(ls $KEYFOLDER); do
        user=${key%.*}
        cat "$ENCFOLDER/$user.enc" | openssl rsautl -decrypt -inkey "$KEYFOLDER/$key"
    done

Solution
--------
Make sure that you have enough prime numbers pre stored to not use one twice when generating keys and get rid of them after use.
So you might as well always compute fresh ones for each new key.
