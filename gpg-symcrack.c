#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "gpg-file.h"
#include "gpg-packet.h"
#include "gpg-challenge.h"
#include "gpg-crypto.h"

int main_test(int argc, char **argv) {
	if(argc < 2) {
		printf("test <challenge.bin-in> <password> - Test a password on a challenge file\n");
		return 1;
	}
	const char *in = argv[0];
	const char *pw = argv[1];
	gpg_challenge c = gpg_challenge_read(in);

	gpg_crypto_hasher h = gpg_crypto_hasher_new(c.hash_algo);
	uint8_t out[h.outbytes];
	h.init(&h);
	h.update(&h, pw, strlen(pw));
	h.final(&h, out);
	gpg_crypto_hasher_delete(&h);


	uint32_t i;
	for(i = 0; i < sizeof(out); i++)
		printf("%02x", out[i]);
	printf("\n");

	printf("haha lol I was just joking :3 %i %s\n", c.sym_algo, pw);
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
	printf("\t"); main_convert(0, NULL);
	printf("\t"); main_test(0, NULL);
	return 1;
}
int main(int argc, char **argv) {
	if(argc < 2) {
		return help(argv[0]);
	}
	if(!strcmp(argv[1], "convert"))
		return main_convert(argc-2, argv+2);
	else if(!strcmp(argv[1], "test"))
		return main_test(argc-2, argv+2);
	else
		return help(argv[0]);
}
