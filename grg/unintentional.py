#!/usr/bin/env python3

from requests import Session
from base64 import urlsafe_b64encode, urlsafe_b64decode
from operator import xor

import re


BLOCK_SIZE = 16
COOKIE_CIPHER = "C-37g56JmOANzMc8wMspBhoLae2wcPEkPO74TJe0kPmovVwC1SN7dVNVgsd0hURzyb6RklkDqemGgdb5_FrnhLQISPu7w7__DLDtQZZfRDW9kArEJr8YvZ5LfMpPtM6WuHRD9VsqfnAnsN7KqlQk1ndFKk1mpn5qEyktQP-I8O0="
BASE_URL = 'http://grg.wutctf.space/'
TARGET_URL = BASE_URL + '/uyulala'
SESSION = Session()


def chop(lst, size):
    return [ lst[i:i+size] for i in range(0, len(lst), size) ]


def oracle(cookie):
    no = 'Decryption failed'
    SESSION.cookies.set('session', cookie)
    res = SESSION.get(TARGET_URL)
    for line in res.text.split('\n'):
        if re.search(r'dark-panel', line):
            print(line)
    return no not in res.text

def main():
    tokens = chop(urlsafe_b64decode(COOKIE_CIPHER), BLOCK_SIZE)
    print(oracle(COOKIE_CIPHER))
    print()

    d_block = tokens[1]
    g_block = tokens[0]

    idx = len(g_block) - 1
    manipulatee = g_block[idx]
    for guess in range(256):
        block = g_block[:idx] + xor(manipulatee, guess).to_bytes(1, 'big') + g_block[idx+1:]
        payload = b''.join([block] + [d_block] + tokens[2:])
        payload = str(urlsafe_b64encode(payload))
        payload = payload[2:len(payload)-1]
        print(oracle(payload))


if __name__ == '__main__':
    main()


# <div class="dark-panel">Welcome atreyu, the reward for your courage is this mystical flag: <code>gg_y0u_pas53d_th3_gat3_bu7_th3_journ3y_b3gin5_n0w</code></div>
