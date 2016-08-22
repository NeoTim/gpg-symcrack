#ifndef _GPG_PACKET_H
#define _GPG_PACKET_H

#include "gpg-file.h"

#define GPG_PACKET_OLD false
#define GPG_PACKET_NEW true

typedef struct gpg_packet_t {
	bool format;
	bool partial;
	uint8_t tag;
	uint32_t length;
	uint8_t *data;
} gpg_packet;

void gpg_packet_free(gpg_packet *p);
gpg_packet gpg_packet_read(gpg_file *f);

#endif
