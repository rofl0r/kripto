#ifndef KRIPTO_SCRYPT_H
#define KRIPTO_SCRYPT_H

#include <kripto/mac.h>

extern int kripto_scrypt
(
	kripto_mac_desc *mac,
	const void *f,
	unsigned int rounds,
	uint64_t n,
	uint32_t r,
	uint32_t p,
	const void *pass,
	unsigned int pass_len,
	const void *salt,
	unsigned int salt_len,
	void *out,
	size_t out_len
);

#endif
