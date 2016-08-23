#include "gpg-s2k.h"
#include "gpg-packet.h"
#include "gpg-crypto.h"

#include <assert.h>
#include <string.h>

// TODO: split into context setup and execution:
// Context: Hasher types, setupts
// Execution: Copy hasher, use pw
void gpg_s2k_salted_iterated(uint8_t *outkey, const gpg_challenge *c, const char *pw) {
	int pwlen = strlen(pw);
	// step 1: create tohash
	uint8_t prototype[pwlen+8];
	int prototypen = pwlen + 8;
	memcpy(prototype, c->salt, 8);
	memcpy(prototype+8, pw, pwlen);
	uint8_t tohash[c->count];

	uint32_t i;
	// Copy most
	for(i = 0; i < c->count/prototypen; i++) {
		memcpy(tohash + i*prototypen, prototype, prototypen);
	}
	// Copy remainder
	memcpy(tohash + i*prototypen, prototype, (c->count - i*prototypen));

	// step 2: find num contexts and set them up.
	int hashlen = gpg_packet_hashsize(c->hash_algo);
	int keylen  = gpg_packet_keysize(c->sym_algo);
	// Divide but round up. More key, more context. More hash, less context
	uint32_t contexts = ((keylen-1)/hashlen) + 1;
	assert(contexts > 0);
	gpg_crypto_hasher hashers[contexts];
	for(i = 0; i < contexts; i++) {
		hashers[i] = gpg_crypto_hasher_new(c->hash_algo);
		hashers[i].init(&hashers[i]);
		if(i > 0) {
			uint8_t zero[i];
			memset(zero, 0, i);
			hashers[i].update(&hashers[i], zero, i);
		}
	}

	// step 3: hash everything
	for(i = 0; i < contexts; i++) {
		hashers[i].update(&hashers[i], tohash, c->count);
	}
	uint8_t key[contexts*hashlen];
	for(i = 0; i < contexts; i++) {
		hashers[i].final(&hashers[i], key + i*hashlen);
	}

	// step 4: copy to outkey
	memcpy(outkey, key, keylen);
}

void gpg_s2k(uint8_t *outkey, const gpg_challenge *c, const char *pw) {
	switch(c->s2k_type) {
		case GPG_S2K_SALTED_ITERATED:
			return gpg_s2k_salted_iterated(outkey, c, pw);
		default:
			assert(0);
	}
}
