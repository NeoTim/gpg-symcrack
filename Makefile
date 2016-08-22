CC=gcc
#CFLAGS=-O3 -march=native -Wall -Wextra -Werror
CFLAGS=-O3 -g3 -Wall -Wextra -Werror `pkg-config --cflags glib-2.0`
LDLIBS=`pkg-config --libs glib-2.0`

.PHONY: all clean


all: gpg-symcrack

clean:
	rm -f gpg-symcrack *.o

gpg-symcrack: gpg-symcrack.o gpg-file.o gpg-packet.o
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@

gpg-file.o: gpg-file.c gpg-file.h gpg-packet.h

gpg-packet.o: gpg-packet.c gpg-packet.h gpg-file.h

gpg-symcrack.o: gpg-symcrack.c gpg-file.h
