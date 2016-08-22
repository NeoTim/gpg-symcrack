#include "gpg-crypto.h"
#include "gpg-packet.h"
#include "crypto/sha1.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>


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
