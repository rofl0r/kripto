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

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <kripto/hash.h>
#include <kripto/hash/sha1.h>

int main(void)
{
	uint8_t hash[20];
	unsigned int i;

	/* 160 */
	puts("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
	kripto_hash_all(kripto_hash_sha1, 0, "The quick brown fox jumps over the lazy dog", 43, hash, 20);
	for(i = 0; i < 20; i++) printf("%.2x", hash[i]);
	putchar('\n');

	return 0;
}
