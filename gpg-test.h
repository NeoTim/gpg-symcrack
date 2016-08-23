#ifndef _GPG_TEST_H
#define _GPG_TEST_H

#include "gpg-challenge.h"
#include "gpg-s2k.h"
#include "gpg-crypto.h"

#include <stdbool.h>

typedef struct {
	gpg_challenge ch;
	gpg_s2k_state s2k;
	gpg_crypto_state crypto;
} gpg_test_state;

gpg_test_state gpg_test_new(const gpg_challenge c);
// Fills in the password
void gpg_test_setpw(gpg_test_state *ts, const char *pw);
// Checks the two bytes
bool gpg_test_test1(gpg_test_state *ts);
// Verifies correctness
bool gpg_test_test2(gpg_test_state *ts);

void gpg_test_delete(gpg_test_state *ts);

#endif
