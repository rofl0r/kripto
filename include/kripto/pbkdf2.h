#ifndef KRIPTO_PBKDF2_H
#define KRIPTO_PBKDF2_H

#include <kripto/mac.h>

extern int kripto_pbkdf2
(
	kripto_mac_desc *mac_desc,
	const void *f,
	unsigned int r,
	unsigned int iter,
	const void *pass,
	unsigned int pass_len,
	const void *salt,
	unsigned int salt_len,
	void *out,
	size_t out_len
);

#endif
