#ifndef _GPG_S2K_H
#define _GPG_S2K_H

#include "gpg-challenge.h"
#include "gpg-crypto.h"

#define MAXCONTEXTS 4

typedef struct {
	uint8_t type; // s2k type
	int hashlen;
	int keylen;
	uint8_t salt[8];
	uint32_t count;
	uint8_t contexts; // number of hasher contexts. Worst case scenario at this point is MD5(16b) vs AES256(32)
	gpg_crypto_hasher h[MAXCONTEXTS];
} gpg_s2k_state;

gpg_s2k_state gpg_s2k_new(const gpg_challenge *c);
void gpg_s2k_free(gpg_s2k_state *s);
void gpg_s2k(gpg_s2k_state *s, uint8_t *outkey, const char *pw);

#endif
