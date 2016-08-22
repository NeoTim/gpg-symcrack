#ifndef _GPG_FILE_H
#define _GPG_FILE_H

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

#define GPG_FILE_BINARY 1
#define GPG_FILE_ARMOR  2

typedef struct gpg_file_t {
	FILE *fp;
	// Bytes that have been decoded but not returned
	// Only in use with GPG_FILE_ARMOR
	uint8_t ibuf[BUFSIZ];
	int ibufn;
	uint8_t obuf[BUFSIZ];
	int obufn;
	int32_t  gbase64_state;
	uint32_t gbase64_save;

	int type; // GPG_FILE_BINARY, GPG_FILE_ARMOR
} gpg_file;

// bool: return false if there is an error
void     gpg_file_fill_buffer(gpg_file *f);
gpg_file gpg_file_open(const char *fname);
bool     gpg_file_error(gpg_file *f);
void     gpg_file_close(gpg_file *f);
// Remember to free()
char    *gpg_file_extract_line(gpg_file *f);
uint32_t gpg_file_read(gpg_file *f, void *buf, uint32_t bufn);

void     gpg_file_armor_start(gpg_file *f);
// Function does not free csumline
void     gpg_file_armor_end(gpg_file *f, char *csumline);
void     gpg_file_armor_read(gpg_file *f);

#endif
