#include "gpg-s2k.h"
#include "gpg-packet.h"
#include "gpg-crypto.h"

#include <assert.h>
#include <string.h>

void gpg_s2k(gpg_s2k_state *s, uint8_t *outkey, const char *pw) {
	int len = strlen(pw);
	switch(s->type) {
		case GPG_S2K_SALTED_ITERATED:
			{
				// step 1: create tohash
				uint8_t prototype[len+8];
				memcpy(prototype, s->salt, 8);
				memcpy(prototype+8, pw, len);
				len += 8; // count len as the whole prototype

				uint8_t tohash[s->count];

				uint32_t i;
				// Copy most
				for(i = 0; i < s->count/len; i++) {
					memcpy(tohash + i*len, prototype, len);
				}
				// Copy remainder
				memcpy(tohash + i*len, prototype, (s->count - i*len));

				// We have preinitialized hashers but need to copy them now
				gpg_crypto_hasher h[s->contexts];
				for(i = 0; i < s->contexts; i++) {
					h[i] = gpg_crypto_hasher_copy(&s->h[i]);
				}

				uint8_t key[s->contexts*s->hashlen];
				// step 3: hash everything
				for(i = 0; i < s->contexts; i++) {
					h[i].update(&h[i], tohash, s->count);
					h[i].final(&h[i], key + i*s->hashlen);
					gpg_crypto_hasher_delete(&h[i]);
				}

				// step 4: copy to outkey
				memcpy(outkey, key, s->keylen);
				return;
			}
		default:
			assert(0);
	}
}

// State is independent of type
gpg_s2k_state gpg_s2k_new(const gpg_challenge *c) {
	gpg_s2k_state ret;
	ret.type = c->s2k_type;
	memcpy(ret.salt, c->salt, 8);
	ret.count = c->count;

	// step 2: find num contexts and set them up.
	ret.hashlen = gpg_packet_hashsize(c->hash_algo);
	ret.keylen  = gpg_packet_keysize(c->sym_algo);

	// Divide but round up. More key, more context. More hash, less context
	ret.contexts = ((ret.keylen-1)/ret.hashlen) + 1;

	assert(ret.contexts > 0);
	assert(ret.contexts <= MAXCONTEXTS);

	uint32_t i;
	for(i = 0; i < ret.contexts; i++) {
		ret.h[i] = gpg_crypto_hasher_new(c->hash_algo);
		ret.h[i].init(&ret.h[i]);
		if(i > 0) {
			uint8_t zero[i];
			memset(zero, 0, i);
			ret.h[i].update(&ret.h[i], zero, i);
		}
	}
	return ret;
}

void gpg_s2k_free(gpg_s2k_state *s) {
	int i;
	for(i = 0; i < s->contexts; i++) {
		gpg_crypto_hasher_delete(&s->h[i]);
	}
}
