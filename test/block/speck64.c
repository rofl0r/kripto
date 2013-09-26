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

#include <kripto/block/speck64.h>

int main(void)
{
	kripto_block *s;
	unsigned int i;
	uint8_t t[8];
	const uint8_t k[16] =
	{
		0x1B, 0x1A, 0x19, 0x18, 0x13, 0x12, 0x11, 0x10,
		0x0B, 0x0A, 0x09, 0x08, 0x03, 0x02, 0x01, 0x00
	};
	const uint8_t pt96[8] =
	{
		0x74, 0x61, 0x46, 0x20, 0x73, 0x6E, 0x61, 0x65
	};
	const uint8_t pt128[8] =
	{
		0x3B, 0x72, 0x65, 0x74, 0x74, 0x75, 0x43, 0x2D
	};
	const uint8_t ct96[8] =
	{
		0x9F, 0x79, 0x52, 0xEC, 0x41, 0x75, 0x94, 0x6C
	};
	const uint8_t ct128[8] =
	{
		0x8C, 0x6F, 0xA5, 0x48, 0x45, 0x4E, 0x02, 0x8B
	};

	puts("kripto_block_speck64");

	/* 96-bit key */
	s = kripto_block_create(kripto_block_speck64, 0, k + 4, 12);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt96, t);
	for(i = 0; i < 8; i++) if(t[i] != ct96[i])
	{
		puts("96-bit key encrypt: FAIL");
		break;
	}
	if(i == 8) puts("96-bit key encrypt: OK");

	kripto_block_decrypt(s, ct96, t);
	for(i = 0; i < 8; i++) if(t[i] != pt96[i])
	{
		puts("96-bit key decrypt: FAIL");
		break;
	}
	if(i == 8) puts("96-bit key decrypt: OK");

	/* 128-bit key */
	s = kripto_block_recreate(s, 0, k, 16);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt128, t);
	for(i = 0; i < 8; i++) if(t[i] != ct128[i])
	{
		puts("128-bit key encrypt: FAIL");
		break;
	}
	if(i == 8) puts("128-bit key encrypt: OK");

	kripto_block_decrypt(s, ct128, t);
	for(i = 0; i < 8; i++) if(t[i] != pt128[i])
	{
		puts("128-bit key decrypt: FAIL");
		break;
	}
	if(i == 8) puts("128-bit key decrypt: OK");

	kripto_block_destroy(s);

	return 0;
}
