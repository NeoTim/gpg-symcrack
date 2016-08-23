#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "gpg-file.h"
#include "gpg-packet.h"
#include "gpg-challenge.h"
#include "gpg-crypto.h"
#include "gpg-s2k.h"

int main_test(int argc, char **argv) {
	if(argc < 2) {
		printf("test <challenge.bin-in> <password> - Test a password on a challenge file\n");
		return 1;
	}
	const char *in = argv[0];
	const char *pw = argv[1];
	gpg_challenge c = gpg_challenge_read(in);

	// Make the key
	uint8_t key[gpg_packet_keysize(c.sym_algo)];
	gpg_s2k_state s2k = gpg_s2k_new(&c);
	gpg_s2k(&s2k, key, pw);
	gpg_s2k_free(&s2k);

	// Make aes
	gpg_crypto_state cs = gpg_crypto_new(c.sym_algo);
	gpg_crypto_key(&cs, key);

	// Execute some steps
	uint8_t FR[cs.blocksize];
	uint8_t plain[cs.blocksize];
	uint16_t cmp1, cmp2;

	memset(FR, 0, cs.blocksize);                    // 1 set zero IV
	gpg_crypto_iv(&cs, FR);
	gpg_crypto_decrypt(&cs, c.data, plain);		// 2 decrypt c.data
	memcpy(&cmp1, plain+cs.blocksize-2, 2);		// 3 save 1
	gpg_crypto_iv(&cs, c.data);			// 4 iv with c.data
	gpg_crypto_decrypt(&cs,
			c.data+cs.blocksize, plain);	// 5 decrypt c.data+cs.blocksize
	memcpy(&cmp2, plain, 2);			// 6 save 2
	printf("%i vs %i\n", cmp1, cmp2);

	gpg_crypto_delete(&cs);

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
	gpg_crypto_init();
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
