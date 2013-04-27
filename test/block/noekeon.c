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

#include <kripto/block.h>
#include <kripto/block/noekeon.h>

#if defined(_TEST) || defined(_PERF)

#ifdef _PERF

#ifndef _CPU
#define _CPU 2000
#endif

#ifndef ITERATIONS
#define ITERATIONS 10000000
#endif

#include <time.h>

#endif

#include <stdio.h>

int main(void)
{
	kripto_block_noekeon_t s;
	unsigned int i;
	uint8_t t[16] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	const uint8_t kc[16] = {
		0x1C, 0x1C, 0x1C, 0x1C, 0x1C, 0x1C, 0x1C, 0x1C,
		0x1C, 0x1C, 0x1C, 0x1C, 0x1C, 0x1C, 0x1C, 0x1C
	};
	#ifdef _TEST
	#ifdef NOEKEON_DIRECT
	const uint8_t p[16] = {
		0x61, 0x39, 0x6C, 0x93, 0x63, 0x74, 0x34, 0xB8,
		0xFC, 0x65, 0x59, 0xA9, 0x5B, 0x64, 0x3F, 0x2C
	};
	#else
	const uint8_t p[16] = {
		0x7A, 0xFE, 0x55, 0x8A, 0x46, 0xFE, 0x07, 0x6E,
		0x35, 0x62, 0x35, 0xF5, 0x9F, 0x32, 0xE7, 0xCC
	};
	#endif
	#endif
	#ifdef _PERF
	clock_t c;
	#endif

	puts("Noekeon");

	s.r = NOEKEON_DEFAULT_ROUNDS;
	kripto_block_noekeon_setup(&s, kc, 16);

	#ifdef _TEST
	kripto_block_noekeon_encrypt(&s, p, t);
	for(i = 0; i < 16; i++) if(t[i] != kc[i])
	{
		puts("128-bit key encrypt: FAIL");
		break;
	}
	if(i == 16) puts("128-bit key encrypt: OK");
	kripto_block_noekeon_decrypt(&s, kc, t);
	for(i = 0; i < 16; i++) if(t[i] != p[i])
	{
		puts("128-bit key decrypt: FAIL");
		break;
	}
	if(i == 16) puts("128-bit key decrypt: OK");
	#endif

	#ifdef _PERF
	c = clock();
	for(i = 0; i < ITERATIONS; i++) kripto_block_noekeon_encrypt(&s, t, t);
	c = clock() - c;

	printf("128 bit key encrypt: %.1f cycles/byte, %.1f MB/s\n",
		(float)c / (float)(ITERATIONS * 16) * _CPU,
		(float)(ITERATIONS * 16) / ((float)c / (float)CLOCKS_PER_SEC) / 1000000.0);

	c = clock();
	for(i = 0; i < ITERATIONS; i++) kripto_block_noekeon_decrypt(&s, t, t);
	c = clock() - c;

	printf("128 bit key decrypt: %.1f cycles/byte, %.1f MB/s\n",
		(float)c / (float)(ITERATIONS * 16) * _CPU,
		(float)(ITERATIONS * 16) / ((float)c / (float)CLOCKS_PER_SEC) / 1000000.0);
	#endif

	return(0);
}

#endif
