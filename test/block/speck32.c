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

#include <kripto/block/speck32.h>

int main(void)
{
	kripto_block *s;
	unsigned int i;
	uint8_t t[4];
	const uint8_t k[8] =
	{
		0x19, 0x18, 0x11, 0x10, 0x09, 0x08, 0x01, 0x00
	};
	const uint8_t pt[4] = {0x65, 0x74, 0x69, 0x4C};
	const uint8_t ct[4] = {0xA8, 0x68, 0x42, 0xF2};

	puts("kripto_block_speck32");

	/* 64-bit key */
	s = kripto_block_create(kripto_block_speck32, 0, k, 8);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt, t);
	for(i = 0; i < 4; i++) if(t[i] != ct[i])
	{
		puts("64-bit key encrypt: FAIL");
		break;
	}
	if(i == 4) puts("64-bit key encrypt: OK");

	kripto_block_decrypt(s, ct, t);
	for(i = 0; i < 4; i++) if(t[i] != pt[i])
	{
		puts("64-bit key decrypt: FAIL");
		break;
	}
	if(i == 4) puts("64-bit key decrypt: OK");

	kripto_block_destroy(s);

	return 0;
}
