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

#include <kripto/block/simon128.h>

int main(void)
{
	kripto_block *s;
	unsigned int i;
	uint8_t t[16];
	const uint8_t k[32] =
	{
		0x1F, 0x1E, 0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18,
		0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
		0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
		0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
	};
	const uint8_t pt128[16] =
	{
		0x63, 0x73, 0x65, 0x64, 0x20, 0x73, 0x72, 0x65,
		0x6C, 0x6C, 0x65, 0x76, 0x61, 0x72, 0x74, 0x20
	};
	const uint8_t pt192[16] =
	{
		0x20, 0x65, 0x72, 0x65, 0x68, 0x74, 0x20, 0x6E,
		0x65, 0x68, 0x77, 0x20, 0x65, 0x62, 0x69, 0x72
	};
	const uint8_t pt256[16] =
	{
		0x74, 0x20, 0x6E, 0x69, 0x20, 0x6D, 0x6F, 0x6F,
		0x6D, 0x69, 0x73, 0x20, 0x61, 0x20, 0x73, 0x69
	};
	const uint8_t ct128[16] =
	{
		0x49, 0x68, 0x1B, 0x1E, 0x1E, 0x54, 0xFE, 0x3F,
		0x65, 0xAA, 0x83, 0x2A, 0xF8, 0x4E, 0x0B, 0xBC
	};
	const uint8_t ct192[16] =
	{
		0xC4, 0xAC, 0x61, 0xEF, 0xFC, 0xDC, 0x0D, 0x4F,
		0x6C, 0x9C, 0x8D, 0x6E, 0x25, 0x97, 0xB8, 0x5B
	};
	const uint8_t ct256[16] =
	{
		0x8D, 0x2B, 0x55, 0x79, 0xAF, 0xC8, 0xA3, 0xA0,
		0x3B, 0xF7, 0x2A, 0x87, 0xEF, 0xE7, 0xB8, 0x68
	};

	puts("kripto_block_simon128");

	/* 128-bit key */
	s = kripto_block_create(kripto_block_simon128, 0, k + 16, 16);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt128, t);
	for(i = 0; i < 16; i++) if(t[i] != ct128[i])
	{
		puts("128-bit key encrypt: FAIL");
		break;
	}
	if(i == 16) puts("128-bit key encrypt: OK");

	kripto_block_decrypt(s, ct128, t);
	for(i = 0; i < 16; i++) if(t[i] != pt128[i])
	{
		puts("128-bit key decrypt: FAIL");
		break;
	}
	if(i == 16) puts("128-bit key decrypt: OK");

	/* 192-bit key */
	s = kripto_block_recreate(s, 0, k + 8, 24);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt192, t);
	for(i = 0; i < 16; i++) if(t[i] != ct192[i])
	{
		puts("192-bit key encrypt: FAIL");
		break;
	}
	if(i == 16) puts("192-bit key encrypt: OK");

	kripto_block_decrypt(s, ct192, t);
	for(i = 0; i < 16; i++) if(t[i] != pt192[i])
	{
		puts("192-bit key decrypt: FAIL");
		break;
	}
	if(i == 16) puts("192-bit key decrypt: OK");

	/* 256-bit key */
	s = kripto_block_recreate(s, 0, k, 32);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt256, t);
	for(i = 0; i < 16; i++) if(t[i] != ct256[i])
	{
		puts("256-bit key encrypt: FAIL");
		break;
	}
	if(i == 16) puts("256-bit key encrypt: OK");

	kripto_block_decrypt(s, ct256, t);
	for(i = 0; i < 16; i++) if(t[i] != pt256[i])
	{
		puts("256-bit key decrypt: FAIL");
		break;
	}
	if(i == 16) puts("256-bit key decrypt: OK");

	kripto_block_destroy(s);

	return 0;
}
