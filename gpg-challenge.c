#include "gpg-challenge.h"
#include "gpg-packet.h"
#include <memory.h>
#include <assert.h>

gpg_challenge gpg_challenge_read_gpg(const char *fname) {
	gpg_challenge c;
	memset(&c, 0, sizeof(c));
	gpg_file gpgf = gpg_file_open(fname);
	assert(!gpg_file_error(&gpgf));

	// First packet
	gpg_packet p = gpg_packet_read(&gpgf);
	assert(p.tag == 3);
	gpg_packet_tag3 t3 = gpg_packet_to_tag3(&p);
	gpg_packet_free(&p);

	c.sym_algo = t3.sym_algo;
	c.s2k_type = t3.s2k.type;
	c.hash_algo = t3.s2k.hash_algo;
	c.count = t3.s2k.count;
	memcpy(c.salt, t3.s2k.salt, 8);
	c.blocksize = gpg_packet_blocksize(c.sym_algo);

	p = gpg_packet_read(&gpgf);
	assert(p.tag == 18);
	assert(p.data[0] == 1);
	assert(p.length >= (uint32_t)(3 + 2*c.blocksize));
	memcpy(c.data, p.data+1, 2 + 2*c.blocksize);
	c.datalen = 2 + 2*c.blocksize;
	gpg_packet_free(&p);

	gpg_file_close(&gpgf);
	return c;
}

gpg_challenge gpg_challenge_read(const char *fname) {
	gpg_challenge ret;
	FILE *fp = fopen(fname, "rb");
	assert(fp != NULL);
	assert(fread(&ret, 1, sizeof(ret), fp) == sizeof(ret));
	fclose(fp);
	return ret;
}

void gpg_challenge_write(const gpg_challenge *c, const char *fname) {
	FILE *fp = fopen(fname, "wb");
	assert(fp != NULL);
	fwrite(c, 1, sizeof(gpg_challenge), fp);
	fclose(fp);
}
