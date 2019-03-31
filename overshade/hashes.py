#!/usr/bin/python3
import struct
import hashlib

bites = [ struct.pack("B", i) for i in range(0, 256) ]

def pab(lst, prefix, n, k):
    if prefix.startswith(b"\x00"):
        return

    sh = hashlib.sha1(prefix).hexdigest()
    if sh.endswith("00a450"):
        print("{}: {}".format(prefix, sh))

    if k == 0:
        return

    for i in range(n):
        pab(lst, prefix + lst[i], n, k - 1)

pab(bites, b"", len(bites), 19)
