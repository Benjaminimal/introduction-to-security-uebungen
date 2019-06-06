grg
==============

Overview
--------
We have a website that protects some resource (the flag in this case) behind session based authentication with the credentials being composed of username and password.

Vulnerability
-------------
The session cookie is being encrypted with AES in CBC mode.
This alone is not sufficient to provide a fresh login since an encrypted cookie can just be resent to authenticate.
To counter this the application includes a time stamp in the cookie and verifies its freshness through it.
However as you will see in the next section this is not enough.  
The vulnerability We were supposed to exploit builds on how CBC mode works.
Since a block of ciphertext is transformed to plaintext by decrypting it and xoring it with the previous block of ciphertext we can manipulate the bytes of the previous block by reversing the xor with our guess, send it to the server and look at the response text.
The program actually gives us a different answer depending on the type of error that occurred.
So when a padding error occurs we know that our guess is wrong, otherwise we guessed the byte and keep going to the next one until the block is decrypted and we keep doing this block for block.

Exploitation
------------
I started fiddling around in python to implement this padding oracle attack and managed to get hold of the flag during that process by accident without actually implementing the planned attack.
Without looping over any blocks or bytes I just tried to implement the process of guessing a single byte and while doing so I inserted a few print statements showing the response text into my oracle function to validate some assumptions.
This led to the flag being spilled in the response since I was manipulating a part of the ciphertext that would influence the timestamp part of the cookie (at least that's what I guess happened).
So I stashed that little accident script and wrote a new one specifically for this type of exploit.

Here is the original exploit

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

And here the 2nd generation

    #!/usr/bin/env python3

    from requests import Session
    from base64 import urlsafe_b64encode, urlsafe_b64decode

    import sys
    import re


    COOKIE_CIPHER = "C-37g56JmOANzMc8wMspBhoLae2wcPEkPO74TJe0kPmovVwC1SN7dVNVgsd0hURzyb6RklkDqemGgdb5_FrnhLQISPu7w7__DLDtQZZfRDW9kArEJr8YvZ5LfMpPtM6WuHRD9VsqfnAnsN7KqlQk1ndFKk1mpn5qEyktQP-I8O0="
    BASE_URL = 'http://grg.wutctf.space/'
    TARGET_URL = BASE_URL + '/uyulala'
    SESSION = Session()


    def get_flag(cookie):
        SESSION.cookies.set('session', cookie)
        res = SESSION.get(TARGET_URL)
        for line in res.text.split('\n'):
            if re.search(r'dark-panel', line) and not re.search(r'(Malformed|Descryption|Invalid|Session)', line):
                return line
        return None

    def main():
        for idx, bite in enumerate(urlsafe_b64decode(COOKIE_CIPHER)):
            cookie = bytearray(urlsafe_b64decode(COOKIE_CIPHER))
            for guess in range(256):
                cookie[idx] = guess
                payload = str(urlsafe_b64encode(cookie))
                payload = payload[2:len(payload)-1]
                flag = get_flag(payload)
                if flag:
                    print("Cookie: session={}\nFlag: {}".format(payload, flag))
                    sys.exit()


    if __name__ == '__main__':
        main()

Solution
--------
I see two options for the block cipher mode issue:
    - unify error messages sent to the client
    - use a different mode, i.e. Cipher Feedback

For the issue with the modifiable timestamp signing the session might fix it.
