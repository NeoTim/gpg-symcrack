#ifndef _GPG_S2K_H
#define _GPG_S2K_H

#include "gpg-challenge.h"

void gpg_s2k(uint8_t *outkey, const gpg_challenge *c, const char *pw);

#endif
