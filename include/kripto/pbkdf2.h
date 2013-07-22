#ifndef KRIPTO_PBKDF2_H
#define KRIPTO_PBKDF2_H

#include <kripto/mac.h>

extern int kripto_pbkdf2
(
	kripto_mac_desc *mac_desc,
	const void *f,
	const unsigned int r,
	const unsigned int iter,
	const void *pass,
	const unsigned int pass_len,
	const void *salt,
	const unsigned int salt_len,
	void *out,
	unsigned int out_len
);

#endif
