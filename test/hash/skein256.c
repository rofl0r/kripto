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
#include <kripto/hash/skein256.h>

int main(void)
{
	uint8_t hash[32];
	unsigned int i;

	puts("34E2B65BF0BE667CA5DEBA82C37CB253EB9F8474F3426BA622A25219FD182433");
	kripto_hash_all(kripto_hash_skein256, 0, "\x0", 1, hash, 32);
	for(i = 0; i < 32; i++) printf("%.2X", hash[i]);
	putchar('\n');

	return 0;
}
