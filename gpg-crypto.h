#ifndef _GPG_CRYPTO_H
#define _GPG_CRYPTO_H

#include <stdint.h>
// Goal: Use a hashing algorithm generically
// gpg_crypto_hasher h = gpg_crypto_hasher_new(GPG_HASH_ALGO_SHA1);
// h.init(&h);
// uint8_t result[h.outbytes];
// h.update(&h, data, len);
// h.final(&h, result);

typedef struct gpg_crypto_hasher_t gpg_crypto_hasher;

struct gpg_crypto_hasher_t {
	int type; // GPG_HASH_ALGO_*
	int outbytes;

	void (*init)  (gpg_crypto_hasher*);
	void (*update)(gpg_crypto_hasher*, const void*, uint32_t); // private, bytes, length
	void (*final) (gpg_crypto_hasher*, void*); // private, out array with size outbytes
	void *private;
};

gpg_crypto_hasher gpg_crypto_hasher_new(int type);
gpg_crypto_hasher gpg_crypto_hasher_copy(gpg_crypto_hasher *src);
void gpg_crypto_hasher_delete(gpg_crypto_hasher *src);

#endif
