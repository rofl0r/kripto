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

/* gcc -Wall -Wextra -ansi -pedantic aes.c -Iinclude libkripto.a */
#include <stdint.h>
#include <time.h>
#include <stdio.h>

#include <kripto/block_aes.h>

#ifndef CPU
#define CPU 2000
#endif

#ifndef ITERATIONS
#define ITERATIONS 10000000
#endif

int main(void)
{
	kripto_block_t s;
	unsigned int i;
	unsigned int n;
	uint8_t t[16] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	const uint8_t k[32] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
	};
	clock_t c;

	puts("kripto_block: AES");

	for(n = 1; n <= 32; n++)
	{
		s = kripto_block_create(kripto_block_aes, k, n, 0);
		if(!s) puts("error");

		c = clock();
		for(i = 0; i < ITERATIONS; i++) kripto_block_encrypt(s, t, t);
		c = clock() - c;

		printf("%u-bit key encrypt: %.1f cycles/byte, %.1f MB/s\n",
			n * 8,
			(float)c / (float)(ITERATIONS * 16) * CPU,
			(float)(ITERATIONS * 16) / ((float)c / (float)CLOCKS_PER_SEC) / 1000000.0);

		c = clock();
		for(i = 0; i < ITERATIONS; i++) kripto_block_decrypt(s, t, t);
		c = clock() - c;

		printf("%u-bit key decrypt: %.1f cycles/byte, %.1f MB/s\n",
			n * 8,
			(float)c / (float)(ITERATIONS * 16) * CPU,
			(float)(ITERATIONS * 16) / ((float)c / (float)CLOCKS_PER_SEC) / 1000000.0);

		kripto_block_destroy(s);
	}

	return 0;
}
