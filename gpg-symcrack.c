#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "gpg-file.h"
#include "gpg-packet.h"
#include "gpg-challenge.h"
#include "gpg-crypto.h"
#include "gpg-s2k.h"
#include "gpg-test.h"

int main_sha1(int argc, char **argv __attribute__((unused))) {
	uint64_t i;

	if(argc < 0) {
		printf("sha1                                           - Test speed of sha1. 12500MiB (same as 100k guesses * 128kB)\n");
		return 1;
	}
	uint8_t test[65536];
	gpg_crypto_hasher h = gpg_crypto_hasher_new(GPG_HASH_ALGO_SHA1);

	h.init(&h);

	memset(test, 0, sizeof(test));
	for(i = 0; i < 2 * 100000; i++)
		h.update(&h, test, sizeof(test));
	uint8_t digest[h.outbytes];

	h.final(&h, digest);
	gpg_crypto_hasher_delete(&h);
	return 0;
}

int main_test2(int argc, char **argv) {
	if(argc < 1) {
		printf("test2   <challenge.bin-in>                     - Test a passwords from stdin. One per line\n");
		return 1;
	}
	const char *in = argv[0];

	gpg_test_state ts = gpg_test_new(gpg_challenge_read(in));

	char pw[BUFSIZ];

	do {
		if(fgets(pw, BUFSIZ, stdin) == NULL)
			break;

		int len;
		for(len = strlen(pw); pw[len-1] == '\n' || pw[len-1] == '\r'; len--) { }
		pw[len] = 0;

		gpg_test_setpw(&ts, pw);
		if(gpg_test_test1(&ts)) {
			printf("Probably correct: '%s'\n", pw);
		}
	} while(1);

	gpg_test_delete(&ts);

	return 0;
}

int main_test(int argc, char **argv) {
	if(argc < 2) {
		printf("test    <challenge.bin-in> <password>          - Test a password on a challenge file\n");
		return 1;
	}
	const char *in = argv[0];
	const char *pw = argv[1];

	gpg_test_state ts = gpg_test_new(gpg_challenge_read(in));

	gpg_test_setpw(&ts, pw);
	if(gpg_test_test1(&ts)) {
		printf("Probably correct password\n");
	} else {
		printf("Wrong password\n");
	}

	gpg_test_delete(&ts);

	return 0;
}

// This was going to convert the information to a hashcat compatible format..
int main_makehash(int argc, char **argv) {
	if(argc < 1) {
		printf("makehash <encrypted.gpg>                       - Convert an encrypted file into a challenge hash, print it\n");
		return 1;
	}
	const char *in = argv[0];
	uint32_t hashsize = 4*16;
	uint8_t hash[hashsize];
	uint32_t i;

	gpg_challenge c = gpg_challenge_read_gpg(in);

	assert(sizeof(c) <= hashsize);
	memset(hash, 0, hashsize);
	memcpy(hash, &c, sizeof(c));
	for(i = 0; i < hashsize; i++) {
		printf("%02x", hash[i]);
	}
	printf("\n");
	return 0;
}

int main_convert(int argc, char **argv) {
	if(argc < 2) {
		printf("convert <encrypted.gpg-in> <challenge.bin-out> - Convert an encrypted file into a challenge file\n");
		return 1;
	}
	const char *in = argv[0];
	const char *out = argv[1];
	gpg_challenge c = gpg_challenge_read_gpg(in);

	gpg_challenge_write(&c, out);
	return 0;
}

int help(const char *program) {
	printf("USAGE: %s <action>\n", program);
	printf("\t"); main_convert(-1, NULL);
	printf("\t"); main_test(-1, NULL);
	printf("\t"); main_test2(-1, NULL);
	printf("\t"); main_sha1(-1, NULL);
	printf("\t"); main_makehash(-1, NULL);
	return 1;
}

int main(int argc, char **argv) {
	gpg_crypto_init();
	if(argc < 2) {
		return help(argv[0]);
	}
	if(!strcmp(argv[1], "convert"))
		return main_convert(argc-2, argv+2);
	else if(!strcmp(argv[1], "test"))
		return main_test(argc-2, argv+2);
	else if(!strcmp(argv[1], "test2"))
		return main_test2(argc-2, argv+2);
	else if(!strcmp(argv[1], "sha1"))
		return main_sha1(argc-2, argv+2);
	else if(!strcmp(argv[1], "makehash"))
		return main_makehash(argc-2, argv+2);
	else
		return help(argv[0]);
}
