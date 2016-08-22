#ifndef _GPG_PACKET_H
#define _GPG_PACKET_H

#include "gpg-file.h"

#define GPG_PACKET_OLD false
#define GPG_PACKET_NEW true

#define GPG_SYM_ALGO_PLAIN	0
#define GPG_SYM_ALGO_IDEA	1
#define GPG_SYM_ALGO_TRIPLEDES	2	// 168 bit key derived from 192
#define GPG_SYM_ALGO_CAST5	3	// 128
#define GPG_SYM_ALGO_BLOWFISH	4	// 128 bit, 16 rounds
#define GPG_SYM_ALGO_AES128	7
#define GPG_SYM_ALGO_AES192	8
#define GPG_SYM_ALGO_AES256	9
#define GPG_SYM_ALGO_TWOFISH	10	// 256 bit

#define GPG_HASH_ALGO_MD5	1
#define GPG_HASH_ALGO_SHA1	2	// SHA160
#define GPG_HASH_ALGO_RIPEMD160	3
#define GPG_HASH_ALGO_SHA256	8
#define GPG_HASH_ALGO_SHA384	9
#define GPG_HASH_ALGO_SHA512	10
#define GPG_HASH_ALGO_SHA224	11

#define GPG_S2K_SIMPLE		0
#define GPG_S2K_SALTED		1
#define GPG_S2K_SALTED_ITERATED	3

typedef struct gpg_packet_t {
	bool format;
	bool partial;
	uint8_t tag;
	uint32_t length;
	uint8_t *data;
} gpg_packet;

typedef struct gpg_packet_s2k_t {
	uint8_t type;
	uint8_t hash_algo;
	uint8_t salt[8];
	uint32_t count;
} gpg_packet_s2k;

#define EXPBIAS 6
#define DECODE_COUNT(c) ((16 + ((c) & 0xf)) << (((c) >> 4) + EXPBIAS))

typedef struct gpg_packet_tag3_t {
	uint8_t version; // always 4
	uint8_t sym_algo;
	gpg_packet_s2k s2k;
	uint8_t skey; // Decrypted with s2k, optional
} gpg_packet_tag3;

void gpg_packet_free(gpg_packet *p);
gpg_packet gpg_packet_read(gpg_file *f);
gpg_packet_tag3 gpg_packet_to_tag3(gpg_packet *p);

int gpg_packet_blocksize(int sym_algo);

#endif
