cryptocat
==============

Overview
--------
The program is a program for secure file transfer. In our case it is listening on the host `10.3.0.5` port `9999`.

Vulnerability
-------------
When receiving a message encrypted with the master key which started with the command for sending data the second token would be the session key which would be used to encrypt the contents of the file (third token) being sent back. This by itself is not a vulnerability but since we had two cipher texts of with partial knowledge of their plain texts and ECB was used a gate opened for us.

Exploitation
------------
By sending the `command_dir` cipher text I managed to get some information about the master key, it's file had a size of 16 bytes so I knew that this had to be the block ciphers block size. Next I split what I assumed to be the plain text versions of the given cipher texts into tokens of the block size to see what parts I could replace or reuse. This showed me that in the `command_snd` the second block contained the tail of the session and a single delimiter character at the end. So all that was left was to replace that with something else that had the same shape where I had the plain and cipher text. Lucky me the `command_dir` seemed to fit that shoe even though I didn't assume so since the plain text needed to execute this command only had a length of 15 bytes but since the cipher text I got had a length of 32 bytes there must have been a delimiter with some junk appended to it. For the final part I needed to decode the flag, since it was sent over in base64, guess the first byte of the session key, decode that and match against a `1337-r3g3X`.

Here is my exploit script:

    #!/usr/bin/env python2
    import sys
    import re

    from base64 import b64decode
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from pwn import pack, remote


    def decrypt(data, key):
        """Decrypt data using the provided key."""

        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(data) + decryptor.finalize()
        return padded_data


    def chop(lst, size):
        return [ lst[i:i+size] for i in range(0, len(lst), size) ]


    def execute_command(payload):
        tube = remote(HOST, PORT)
        tube.sendline(payload)
        return tube.recvall()


    HOST = "cryptocat.wutctf.space"
    PORT = 9999
    CMDS = {
        'DIR': {
            'PATH': b'command_dir',
            'PLAIN': b'show_file_names',
            'CIPHER': b'',
        },
        'SND': {
            'PATH': b'command_snd',
            'PLAIN': b'send_encrypted#????????????????#flag',
            'CIPHER': b'',
        }
    }

    with open(CMDS['DIR']['PATH'], 'rb') as f:
        CMDS['DIR']['CIPHER'] = f.read()

    with open(CMDS['SND']['PATH'], 'rb') as f:
        CMDS['SND']['CIPHER'] = f.read()


    def main():
        print(execute_command(CMDS['DIR']['CIPHER']))

        block_size = 16

        snd_blocks = chop(CMDS['SND']['CIPHER'], block_size)
        print(chop(CMDS['SND']['PLAIN'], block_size))
        print(snd_blocks)
        dir_blocks = chop(CMDS['DIR']['CIPHER'], block_size)
        print(chop(CMDS['DIR']['PLAIN'], block_size))
        print(dir_blocks)
        print

        payload = snd_blocks[0] + dir_blocks[0] + snd_blocks[2]
        response = execute_command(payload)
        print(response)

        lines = response.split('\n')
        b64_flag = lines[len(lines)-2]
        flag = b64decode(b64_flag)

        key = CMDS['DIR']['PLAIN']
        for c in range(1, 256):
            key_candidate = pack(c)[0] + key
            flag_candidate = decrypt(flag, key_candidate)
            if re.match(r'(\w+_)+\w+', flag_candidate):
                print(flag_candidate)
                print(len(flag_candidate))


    if __name__ == '__main__':
        main()

Solution
--------
Replace all instances of `modes.ECB()` with `modes.CBC()`.
