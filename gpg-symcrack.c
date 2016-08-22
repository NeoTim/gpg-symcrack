#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "gpg-file.h"
#include "gpg-packet.h"

// TODO: move to gpg-algorithms
#define MAXBS 16
// TODO: make gpg hashes in gpg-hashes

typedef struct challenge_t {
	uint8_t algorithm; // 9: AES256 CFB
	uint8_t symalg; // How to make key from passphrase. 3 = iterated and salted
	uint8_t hashalg; // Hashing algorithm
	uint32_t bytecount;
	uint8_t salt[8]; // How many bytes to make of salt+pw+salt+pw... in s2k mode

	uint8_t datalen;
	uint8_t data[2+(2*MAXBS)]; // one BS for random values, 2 bytes for check, one BS for verification data
} challenge;

challenge read_challenge(char *fname) {
	challenge c;
	gpg_file gpgf = gpg_file_open(fname);
	assert(!gpg_file_error(&gpgf));

	// First packet
	gpg_packet p = gpg_packet_read(&gpgf);
	printf("New format? %i\n", p.format == GPG_PACKET_NEW);

	gpg_file_close(&gpgf);
	return c;
}

int main(int argc, char **argv) {
	challenge c;
	if(argc < 2) {
		printf("USAGE: %s <file to crack>\n", argv[0]);
		return 1;
	}
	c = read_challenge(argv[1]);
	printf("algorithm %i\n", c.algorithm);
	return 0;
}
