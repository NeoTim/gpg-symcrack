#ifndef _GPG_CRYPTO_H
#define _GPG_CRYPTO_H
#include <stdint.h>
#include <openssl/evp.h>

// ALWAYS call this:
void gpg_crypto_init();

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


typedef struct gpg_crypto_state_t gpg_crypto_state;

struct gpg_crypto_state_t {
	int type; // GPG_SYM_ALGO_*
	int keylen;
	int blocksize;
	EVP_CIPHER_CTX *ctx;
};
// Create a new
gpg_crypto_state gpg_crypto_new(int type);
void gpg_crypto_key(gpg_crypto_state *cs, uint8_t *key);
void gpg_crypto_encrypt(gpg_crypto_state *cs, uint8_t *src, uint8_t *dst);
void gpg_crypto_delete(gpg_crypto_state *cs);

void gpg_crypto_xor(uint8_t *src1, uint8_t *src2, uint8_t *dst, uint32_t size);

#endif
