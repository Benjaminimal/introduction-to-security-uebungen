#!/usr/bin/env python3

import sys
import string
from itertools import product
from hashlib import sha1

s = sys.argv[1]
h = sys.argv[2]
s_pre, s_post = s.split('????')
for c in product(string.ascii_letters + string.digits, repeat=4):
	guess = s_pre + ''.join(c) + s_post
	if sha1(guess.encode()).hexdigest() == h:
		print(''.join(c))
		break
