#include "gpg-crypto.h"
#include "gpg-packet.h"
#include "crypto/sha1.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>

#include <openssl/evp.h>
#include <openssl/err.h>

// Hashing algorithms
void gpg_crypto_sha1_init  (gpg_crypto_hasher *c)                                  { blk_SHA1_Init(c->private);               }
void gpg_crypto_sha1_update(gpg_crypto_hasher *c, const void *bytes, uint32_t len) { blk_SHA1_Update(c->private, bytes, len); }
void gpg_crypto_sha1_final (gpg_crypto_hasher *c, void *out)                       { blk_SHA1_Final(out, c->private);         }

gpg_crypto_hasher gpg_crypto_hasher_new(int type) {
	gpg_crypto_hasher ret;
	ret.type = type;
	switch(type) {
		case GPG_HASH_ALGO_SHA1:
			ret.outbytes = gpg_packet_hashsize(type);
			ret.init     = gpg_crypto_sha1_init;
			ret.update   = gpg_crypto_sha1_update;
			ret.final    = gpg_crypto_sha1_final;
			ret.private  = malloc(sizeof(blk_SHA_CTX));
			break;
		default:
			assert(0);
	}
	return ret;
}

gpg_crypto_hasher gpg_crypto_hasher_copy(gpg_crypto_hasher *src) {
	gpg_crypto_hasher ret = gpg_crypto_hasher_new(src->type);
	switch(src->type) {
		case GPG_HASH_ALGO_SHA1:
			memcpy(ret.private, src->private, sizeof(blk_SHA_CTX));
			break;
		default:
			assert(0);
	}
	return ret;
}

void gpg_crypto_hasher_delete(gpg_crypto_hasher *src) {
	if(src->private)
		free(src->private);
	src->type = 0;
	src->outbytes = 0;
	src->init = NULL;
	src->update = NULL;
	src->final = NULL;
	src->private = NULL;
}

// Encryption algorithms

void gpg_crypto_init() {
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
}

gpg_crypto_state gpg_crypto_new(int type) {
	gpg_crypto_state ret;
	ret.type = type;
	ret.keylen = gpg_packet_keysize(type);
	ret.blocksize = gpg_packet_blocksize(type);
	ret.ctx = EVP_CIPHER_CTX_new();
	assert(ret.ctx != NULL);

	const EVP_CIPHER *cipher;
	switch(type) {
		case GPG_SYM_ALGO_AES256:
			cipher = EVP_aes_256_cfb();
			break;
		default:
			assert(0);
	}

	EVP_DecryptInit_ex(ret.ctx, cipher, NULL, NULL, NULL);
	return ret;
}
void gpg_crypto_key(gpg_crypto_state *cs, uint8_t *key) {
	assert(EVP_DecryptInit_ex(cs->ctx, NULL, NULL, key, NULL));
}
void gpg_crypto_iv(gpg_crypto_state *cs, uint8_t *iv) {
	assert(EVP_DecryptInit_ex(cs->ctx, NULL, NULL, NULL, iv));
}
void gpg_crypto_decrypt(gpg_crypto_state *cs, uint8_t *src, uint8_t *dst) {
	int outlen = cs->blocksize;
	assert(EVP_DecryptUpdate(cs->ctx, dst, &outlen, src, cs->blocksize));
}
void gpg_crypto_delete(gpg_crypto_state *cs) {
	EVP_CIPHER_CTX_free(cs->ctx);
}

void gpg_crypto_xor(uint8_t *s1, uint8_t *s2, uint8_t *dst, uint32_t size) {
	while(size > 0) {
		*dst = *s1 ^ *s2;
		size--;
		dst++; s1++; s2++;
	}
}
