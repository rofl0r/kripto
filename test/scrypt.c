/*
 * Copyright (C) 2013 Gregor Pintar <grpintar@gmail.com>
 *
 * Permission is granted to deal in this work without any restriction,
 * including unlimited rights to use, publicly perform, publish,
 * reproduce, relicence, modify, merge, and/or distribute in any form,
 * for any purpose, with or without fee, and by any means.
 *
 * This work is provided "AS IS" and WITHOUT WARRANTY of any kind,
 * to the utmost extent permitted by applicable law. In no event
 * shall a licensor, author or contributor be held liable for any
 * issues arising in any way out of dealing in the work.
 */

#include <stdint.h>
#include <stdio.h>

#include <kripto/mac/hmac.h>
#include <kripto/hash/sha2_256.h>
#include <kripto/scrypt.h>

int main(void)
{
	const uint8_t out[64] =
	{
		0x21, 0x01, 0xCB, 0x9B, 0x6A, 0x51, 0x1A, 0xAE,
		0xAD, 0xDB, 0xBE, 0x09, 0xCF, 0x70, 0xF8, 0x81,
		0xEC, 0x56, 0x8D, 0x57, 0x4A, 0x2F, 0xFD, 0x4D,
		0xAB, 0xE5, 0xEE, 0x98, 0x20, 0xAD, 0xAA, 0x47,
		0x8E, 0x56, 0xFD, 0x8F, 0x4B, 0xA5, 0xD0, 0x9F,
		0xFA, 0x1C, 0x6D, 0x92, 0x7C, 0x40, 0xF4, 0xC3,
		0x37, 0x30, 0x40, 0x49, 0xE8, 0xA9, 0x52, 0xFB,
		0xCB, 0xF4, 0x5C, 0x6F, 0xA7, 0x7A, 0x41, 0xA4
	};
	uint8_t buf[64];
	unsigned int i;

	if(kripto_scrypt
	(
		kripto_mac_hmac,
		kripto_hash_sha2_256,
		0,
		1048576,
		8,
		1,
		"pleaseletmein",
		13,
		"SodiumChloride",
		14,
		buf,
		64
	))
	{
		perror("kripto_scrypt() returned error");
		return -1;
	}

	for(i = 0; i < 64; i++) if(buf[i] != out[i])
	{
		fputs("kripto_scrypt: FAIL\n", stderr);
		return -1;
	}

	puts("kripto_scrypt: OK");
	return 0;
}
