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

#include <kripto/block/safer.h>
#include <kripto/block/safer_sk.h>

int main(void)
{
	kripto_block *s;
	unsigned int i;
	uint8_t t[8];
	const uint8_t k64[8] =
	{
		0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
	};
	const uint8_t pt[16] =
	{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	const uint8_t ct64[8] =
	{
		0xC8, 0xF2, 0x9C, 0xDD, 0x87, 0x78, 0x3E, 0xD9
	};
	const uint8_t ct64sk[8] =
	{
		0x5F, 0xCE, 0x9B, 0xA2, 0x05, 0x84, 0x38, 0xC7
	};
	const uint8_t ct128sk[8] =
	{
		0xFF, 0x78, 0x11, 0xE4, 0xB3, 0xA7, 0x2E, 0x71
	};

	puts("kripto_block_safer");

	/* 64-bit key */
	s = kripto_block_create(kripto_block_safer, 0, k64, 8);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt, t);
	for(i = 0; i < 8; i++) if(t[i] != ct64[i])
	{
		puts("64-bit key encrypt: FAIL");
		break;
	}
	if(i == 8) puts("64-bit key encrypt: OK");

	kripto_block_decrypt(s, ct64, t);
	for(i = 0; i < 8; i++) if(t[i] != pt[i])
	{
		puts("64-bit key decrypt: FAIL");
		break;
	}
	if(i == 8) puts("64-bit key decrypt: OK");

	kripto_block_destroy(s);

	/* SK */
	puts("\nkripto_block_safer_sk");

	/* 64-bit key */
	s = kripto_block_create(kripto_block_safer_sk, 6, pt, 8);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt, t);
	for(i = 0; i < 8; i++) if(t[i] != ct64sk[i])
	{
		puts("64-bit key encrypt: FAIL");
		break;
	}
	if(i == 8) puts("64-bit key encrypt: OK");

	kripto_block_decrypt(s, ct64sk, t);
	for(i = 0; i < 8; i++) if(t[i] != pt[i])
	{
		puts("64-bit key decrypt: FAIL");
		break;
	}
	if(i == 8) puts("64-bit key decrypt: OK");

	/* 128-bit key */
	s = kripto_block_recreate(s, 0, pt, 16);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt, t);
	for(i = 0; i < 8; i++) if(t[i] != ct128sk[i])
	{
		puts("128-bit key encrypt: FAIL");
		break;
	}
	if(i == 8) puts("128-bit key encrypt: OK");

	kripto_block_decrypt(s, ct128sk, t);
	for(i = 0; i < 8; i++) if(t[i] != pt[i])
	{
		puts("128-bit key decrypt: FAIL");
		break;
	}
	if(i == 8) puts("128-bit key decrypt: OK");

	kripto_block_destroy(s);

	return 0;
}
