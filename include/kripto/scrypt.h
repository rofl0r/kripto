#ifndef KRIPTO_SCRYPT_H
#define KRIPTO_SCRYPT_H

extern int kripto_scrypt
(
	const kripto_mac_desc *mac,
	unsigned int mac_rounds,
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
