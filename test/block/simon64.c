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

#include <kripto/block/simon64.h>

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
		0x6F, 0x72, 0x20, 0x67, 0x6E, 0x69, 0x6C, 0x63
	};
	const uint8_t pt128[8] =
	{
		0x65, 0x6B, 0x69, 0x6C, 0x20, 0x64, 0x6E, 0x75
	};
	const uint8_t ct96[8] =
	{
		0x5C, 0xA2, 0xE2, 0x7F, 0x11, 0x1A, 0x8F, 0xC8
	};
	const uint8_t ct128[8] =
	{
		0x44, 0xC8, 0xFC, 0x20, 0xB9, 0xDF, 0xA0, 0x7A
	};

	puts("kripto_block_simon64");

	/* 96-bit key */
	s = kripto_block_create(kripto_block_simon64, 0, k + 4, 12);
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
