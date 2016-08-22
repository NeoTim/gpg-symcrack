#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "gpg-file.h"
#include "gpg-packet.h"
#include "gpg-challenge.h"


int main_load(int argc, char **argv) {
	if(argc < 2) {
		printf("load <encrypted.gpg-in> <challenge.bin-out>\n");
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
	main_load(0, NULL);
	return 1;
}
int main(int argc, char **argv) {
	if(argc < 2) {
		return help(argv[0]);
	}
	if(!strcmp(argv[1], "load"))
		return main_load(argc-2, argv+2);
	else
		return help(argv[0]);
}
