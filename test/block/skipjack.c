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

#include <kripto/block/skipjack.h>

int main(void)
{
	kripto_block *s;
	unsigned int i;
	uint8_t t[8];
	const uint8_t k[10] =
	{
		0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
	};
	const uint8_t pt[8] =
	{
		0x33, 0x22, 0x11, 0x00, 0xDD, 0xCC, 0xBB, 0xAA
	};
	const uint8_t ct[8] =
	{
		0x25, 0x87, 0xCA, 0xE2, 0x7A, 0x12, 0xD3, 0x00
	};

	puts("kripto_block_skipjack");

	s = kripto_block_create(kripto_block_skipjack, 0, k, 10);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt, t);
	for(i = 0; i < 8; i++) if(t[i] != ct[i])
	{
		puts("encrypt: FAIL");
		break;
	}
	if(i == 8) puts("encrypt: OK");

	kripto_block_decrypt(s, ct, t);
	for(i = 0; i < 8; i++) if(t[i] != pt[i])
	{
		puts("decrypt: FAIL");
		break;
	}
	if(i == 8) puts("decrypt: OK");

	kripto_block_destroy(s);

	return 0;
}
