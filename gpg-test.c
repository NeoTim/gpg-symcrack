#include "gpg-test.h"
#include <memory.h>

gpg_test_state gpg_test_new(const gpg_challenge c) {
	gpg_test_state ret;
	ret.ch = c;
	ret.s2k = gpg_s2k_new(&ret.ch);
	ret.crypto = gpg_crypto_new(ret.ch.sym_algo);
	return ret;
}

// Fills in the password
void gpg_test_setpw(gpg_test_state *ts, const char *pw) {
	uint8_t key[ts->crypto.keylen];
	gpg_s2k(&ts->s2k, key, pw);
	gpg_crypto_key(&ts->crypto, key);
}

// Checks the two bytes
bool gpg_test_test1(gpg_test_state *ts) {
	gpg_crypto_state *ctx = &ts->crypto;
	int bs = ctx->blocksize;
	uint8_t plain[bs];

	uint16_t test1, test2;

	memset(plain, 0, bs);
	gpg_crypto_iv(ctx, plain); // iv = 0
	gpg_crypto_decrypt(ctx, ts->ch.data, plain);
	memcpy(&test1, plain+bs-2, 2);

	gpg_crypto_iv(ctx, ts->ch.data);
	gpg_crypto_decrypt(ctx, ts->ch.data+bs, plain);
	memcpy(&test2, plain, 2);

	return test1 == test2;
}

// Verifies correctness
bool gpg_test_test2(gpg_test_state *ts);

void gpg_test_delete(gpg_test_state *ts) {
	gpg_crypto_delete(&ts->crypto);
}
