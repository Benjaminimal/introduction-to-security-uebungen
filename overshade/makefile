CFLAGS=-g -Wall -Wextra -pedantic -ansi -m32 -fno-stack-protector
LIBS=-lcrypto

overshade: overshade.c
	gcc $(CFLAGS) overshade.c -o overshade $(LIBS)

modyshade: modyshade.c
	gcc $(CFLAGS) modyshade.c -o modyshade $(LIBS)
