CC=gcc
CFLAGS=-O3 -march=native -Wall -Wextra -Werror `pkg-config --cflags glib-2.0`
#CFLAGS=-O3 -g3 -Wall -Wextra -Werror `pkg-config --cflags glib-2.0`
LDLIBS=`pkg-config --libs glib-2.0`

.PHONY: all clean


all: gpg-symcrack

clean:
	rm -f gpg-symcrack *.o */*.o

gpg-symcrack: gpg-symcrack.o gpg-file.o gpg-packet.o gpg-challenge.o gpg-crypto.o crypto/sha1.o
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@

gpg-file.o: gpg-file.c gpg-file.h gpg-packet.h

gpg-packet.o: gpg-packet.c gpg-packet.h gpg-file.h

gpg-challenge.o: gpg-challenge.c gpg-challenge.h gpg-packet.h

gpg-symcrack.o: gpg-symcrack.c gpg-file.h gpg-packet.h gpg-challenge.h gpg-crypto.h

crypto/sha1.o: crypto/sha1.c crypto/sha1.h

gpg-crypto.o: gpg-crypto.c gpg-crypto.h gpg-packet.h crypto/sha1.h

gpg-packet.h: gpg-file.h
