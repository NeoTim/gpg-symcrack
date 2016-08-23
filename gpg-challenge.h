#ifndef _GPG_CHALLENGE_H
#define _GPG_CHALLENGE_H

#include <stdint.h>

#define MAXBS 16

typedef struct gpg_challenge_t {
	uint8_t sym_algo;
	uint8_t s2k_type; // How to make key from passphrase. 3 = iterated and salted
	uint8_t hash_algo; // Hashing algorithm
	uint32_t count;
	uint8_t salt[8]; // How many bytes to make of salt+pw+salt+pw... in s2k mode

	uint8_t datalen;
	uint8_t data[2+(2*MAXBS)]; // one BS for random values, 2 bytes for check, one BS for verification data
} gpg_challenge;

gpg_challenge gpg_challenge_read_gpg(const char *fname);
gpg_challenge gpg_challenge_read(const char *fname);
void          gpg_challenge_write(const gpg_challenge *c, const char *fname);

#endif
