#include "gpg-packet.h"
#include <assert.h>
#include <stdlib.h>
#include <endian.h>

//#define GPG_PACKET_OLD false
//#define GPG_PACKET_NEW true

//typedef struct gpg_packet_t {
//	bool format;
//	bool partial;
//	uint8_t tag;
//	uint32_t length;
//	uint8_t *data;
//} gpg_packet;

void gpg_packet_free(gpg_packet *p) {
	if(p->data != NULL)
		free(p->data);

	p->format = GPG_PACKET_OLD;
	p->data = NULL;
	p->length = 0;
	p->tag = 0;
	p->partial = false;
}
gpg_packet gpg_packet_read(gpg_file *f) {
	gpg_packet ret;

	ret.format = GPG_PACKET_OLD;
	ret.data = NULL;
	ret.length = 0;
	ret.tag = 0;
	ret.partial = false;

	uint8_t tag;
	assert(gpg_file_read(f, &tag, 1) == 1);
	assert(tag & 0x80);
	if(tag & 0x40) {
		ret.format = GPG_PACKET_NEW;
		ret.tag = tag & 0x3f;
		uint8_t len1;
		assert(gpg_file_read(f, &len1, 1) == 1);
		ret.partial = false;
		if(len1 < 192) {
			ret.length = len1;
		} else if(len1 < 224) {
			uint8_t len2;
			assert(gpg_file_read(f, &len2, 1) == 1);
			ret.length = ((len1 - 192) << 8) + len2 + 192;
		} else if(len1 < 255) {
			ret.length = 1 << (len1-224);
			ret.partial = true;
		} else {
			uint32_t len4;
			assert(gpg_file_read(f, &len4, 4) == 4);
			ret.length = be32toh(len4);
		}
		ret.data = malloc(ret.length);
		assert(gpg_file_read(f, ret.data, ret.length) == ret.length);
	} else {
		ret.format = GPG_PACKET_OLD;
		ret.tag = (tag >> 2) & 0xf;
		int ltype = tag & 0x3;
		uint8_t len;
		uint16_t len2;
		uint32_t len4;
		switch(ltype) {
			case 0:
				assert(gpg_file_read(f, &len, 1) == 1);
				ret.length = len;
				break;
			case 1:
				assert(gpg_file_read(f, &len2, 2) == 2);
				ret.length = be16toh(len2);
				break;
			case 2:
				assert(gpg_file_read(f, &len4, 4) == 4);
				ret.length = be32toh(len4);
				break;
			case 3:
			default:
				printf("Unsupported length type for old packet (type = 3) :(\n");
				assert(0);
		}
		ret.partial = false;
		ret.data = malloc(ret.length);
		assert(gpg_file_read(f, ret.data, ret.length) == ret.length);
	}
	return ret;
}
