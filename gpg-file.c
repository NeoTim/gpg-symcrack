#include <assert.h>
#include <memory.h>
#include <stdlib.h>
#include "gpg-file.h"
#include <glib.h>

gpg_file gpg_file_open(const char *fname) {
	gpg_file f;
	f.ibufn = 0;
	f.obufn = 0;
	f.gbase64_state = 0;
	f.gbase64_save = 0;
	f.fp = fopen(fname, "rb");
	if(f.fp == NULL) return f; // error

	uint8_t test;
	assert(fread(&test, 1, 1, f.fp) == 1);
	rewind(f.fp);
	if(test & 0x80)
		f.type = GPG_FILE_BINARY;
	else {
		f.type = GPG_FILE_ARMOR;
		gpg_file_armor_start(&f);
	}

	return f;
}
uint32_t gpg_file_read(gpg_file *f, void *buf, uint32_t bufn) {
	if(f->type == GPG_FILE_BINARY) {
		int n = fread(buf, 1, bufn, f->fp);
		if(n <= 0)
			gpg_file_close(f);
		return n;
	} else {
		int total = 0;
		while(bufn > 0) {
			// Try to read
			if(f->obufn == 0)
				gpg_file_armor_read(f);
			// Still nothing? expecting eof
			if(f->obufn == 0)
				break;

			uint32_t tocopy = ((uint32_t)f->obufn < bufn) ? (uint32_t)f->obufn : bufn;
			memcpy(buf, f->obuf, tocopy);
			// Move output
			buf += tocopy;
			bufn -= tocopy;
			// Move input
			uint32_t i;
			for(i = 0; i < f->obufn - tocopy; i++) {
				f->obuf[i] = f->obuf[i+tocopy];
			}
			f->obufn -= tocopy;
			total += tocopy;
		}
		return total;
	}
}

bool gpg_file_error(gpg_file *f) {
	if(f->fp == NULL)
		return true;
	return false;
}
void gpg_file_close(gpg_file *f) {
	if(f->fp) {
		fclose(f->fp);
		f->fp = NULL;
	}
}
void gpg_file_armor_read(gpg_file *f) {
	gpg_file_fill_buffer(f);
	char *l = gpg_file_extract_line(f);
	if(strlen(l) > 1 && l[0]=='=') {
		// Pass the pointer
		gpg_file_armor_end(f, l);
	} else {
		assert((BUFSIZ-f->obufn) >= ((f->ibufn/4)*3 + 3));
		int n = g_base64_decode_step(l, strlen(l),
				f->obuf+f->obufn,
				&f->gbase64_state, &f->gbase64_save);
		f->obufn += n;
	}
	free(l);
}
void gpg_file_armor_end(gpg_file *f, char *l) {
	assert(l[0] == '=' && strlen(l) > 1);
	l++;
	{
		size_t olen = 0;
		uint8_t *o = g_base64_decode(l, &olen);
		assert(olen == 3);
		printf("Armor base64: %02x %02x %02x\n", o[0], o[1], o[2]);
		g_free(o);
	}

	l = gpg_file_extract_line(f);
	assert(!strcmp(l, "-----END PGP MESSAGE-----"));
	free(l);
	gpg_file_close(f);
	f->ibufn = 0;
}
void gpg_file_armor_start(gpg_file *f) {
	// Find the start tag
	while(1) {
		char *l = gpg_file_extract_line(f);
		if(l == NULL) {
			gpg_file_close(f);
			return;
		}
		if(!strcmp(l, "-----BEGIN PGP MESSAGE-----")) {
			free(l);
			break;
		} else {
			free(l);
		}
	}
	// Find an empty line
	while(1) {
		char *l = gpg_file_extract_line(f);
		if(l == NULL) {
			gpg_file_close(f);
			return;
		}
		if(strlen(l) == 0) {
			free(l);
			break;
		} else {
			free(l);
		}
	}
	// Aaaand done
}
char *gpg_file_extract_line(gpg_file *f) {
	gpg_file_fill_buffer(f);
	int n;
	for(n = 0; n < f->ibufn; n++) {
		if(f->ibuf[n] == '\n')
			break;
	}
	// Can't find a line
	if(n == f->ibufn)
		return NULL;
	char *ret = malloc(n+1);
	memcpy(ret, f->ibuf, n);
	ret[n] = 0;
	if(ret[n-1] == '\r')
		ret[n-1] = 0;
	// Then, move the rest of the buffered blocks
	int i;
	n++;
	for(i = 0; i < f->ibufn-n; i++)
		f->ibuf[i] = f->ibuf[i+n];
	f->ibufn -= n;
	return ret;
}
// Guaranteed to fill the buffer unless the file ends
void gpg_file_fill_buffer(gpg_file *f) {
	if(f->fp == NULL)
		return;
	if(f->ibufn == BUFSIZ)
		return;

	int n = fread(f->ibuf+f->ibufn, 1, BUFSIZ-f->ibufn, f->fp);
	if(n <= 0) {
		gpg_file_close(f);
		return;
	}
	f->ibufn += n;
	if(f->ibufn < BUFSIZ)
		gpg_file_fill_buffer(f);
}
