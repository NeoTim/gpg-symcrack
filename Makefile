
PKGCONFIG=glib-2.0 openssl
CC=gcc
CFLAGS=-O3 -march=native -Wall -Wextra -Werror `pkg-config --cflags $(PKGCONFIG)`
LDLIBS=`pkg-config --libs $(PKGCONFIG)`

.PHONY: all clean


all: gpg-symcrack

clean:
	rm -f gpg-symcrack *.o

gpg-symcrack: gpg-challenge.o gpg-crypto.o gpg-file.o gpg-packet.o gpg-s2k.o gpg-symcrack.o gpg-test.o
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@

gpg-challenge.o: gpg-challenge.c gpg-challenge.h gpg-packet.h gpg-file.h

gpg-crypto.o: gpg-crypto.c gpg-crypto.h gpg-packet.h gpg-file.h

gpg-file.o: gpg-file.c gpg-file.h

gpg-packet.o: gpg-packet.c gpg-packet.h gpg-file.h

gpg-s2k.o: gpg-s2k.c gpg-s2k.h gpg-packet.h gpg-crypto.h gpg-file.h gpg-challenge.h

gpg-symcrack.o: gpg-symcrack.c gpg-file.h gpg-packet.h gpg-challenge.h gpg-crypto.h gpg-s2k.h gpg-test.h

gpg-test.o: gpg-test.c gpg-test.h gpg-challenge.h gpg-s2k.h gpg-crypto.h

gpg-packet.h: gpg-file.h

gpg-s2k.h: gpg-challenge.h gpg-crypto.h

gpg-test.h: gpg-challenge.h gpg-s2k.h gpg-crypto.h
