#!/usr/bin/env python3

import sys
from base64 import b64encode
from subprocess import run, PIPE
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# commands supported by the server
CMDS = {
    'DIR': b'show_file_names',
    'SND': b'send_encrypted'
}

# error messages returned by the application
MSGS = {
    'BAD_DEC': 'Decryption failed',
    'BAD_ENC': 'Encryption under session key failed',
    'BAD_CMD': 'Malformed command',
    'UNK_CMD': 'Unknown command',
    'BAD_SKEY_LEN': 'Wrong session key length'
}

# char used to separate and terminate the parts of a command
SEP = ord(b'#')
# path of the master key file
KEY_PATH = 'master_key.bin'


def die(msg):
    """Print an error message and terminate."""

    print('[!] {}, aborting... :('.format(msg))
    sys.exit(1)


def encrypt(data, key):
    """Encrypt data using the provided key."""

    try:
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data)
        padded_data += padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()

        return encryptor.update(padded_data) + encryptor.finalize()

    except Exception:
        die(MSGS['BAD_ENC'])


def decrypt(data, key):
    """Decrypt data using the provided key."""

    try:
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(data) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(padded_data)

        return unpadded_data + unpadder.finalize()

    except Exception:
        die(MSGS['BAD_DEC'])


def parse(data):
    """Parse a protocol command."""

    part = []
    for c in data:
        if c == SEP:
            yield bytes(part)
            part = []
        else:
            part.append(c)


def main():
    """Main function."""

    # get input from stdin
    buf = sys.stdin.buffer.readline().rstrip(b'\n')

    # load the master key
    with open(KEY_PATH, 'rb') as f:
        key = f.read()

    # decrypt under the master key
    msg = decrypt(buf, key)

    # parse the command
    try:
        parts = parse(msg)

        cmd = next(parts)

        if cmd == CMDS['DIR']:
            print('[*] Showing directory listing\n{}'.format('='*79))
            print(run(['ls', '-l'], stdout=PIPE).stdout.decode())

        elif cmd == CMDS['SND']:
            skey = next(parts)
            fname = next(parts)

            if len(skey) != 16:
                die(MSGS['BAD_SKEY_LEN'])
            with open(fname, 'rb') as f:
                data = f.read()
            print('[*] Sending the file "{}" encrypted under the session key\n{}'.format(
                fname.decode(), '='*79))
            print(b64encode(encrypt(data, skey)).decode())

        else:
            die(MSGS['UNK_CMD'])

    except StopIteration:
        die(MSGS['BAD_CMD'])


if __name__ == '__main__':
    main()
