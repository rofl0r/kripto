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
#include <kripto/hash/sha2_256.h>
#include <kripto/hash/sha2_512.h>

int main(void)
{
	uint8_t hash[64];
	unsigned int i;

	/* 224 */
	puts("730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525");
	kripto_hash_all(kripto_hash_sha2_256, 0, "The quick brown fox jumps over the lazy dog", 43, hash, 28);
	for(i = 0; i < 28; i++) printf("%.2x", hash[i]);
	putchar('\n');

	/* 256 */
	puts("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
	kripto_hash_all(kripto_hash_sha2_256, 0, "The quick brown fox jumps over the lazy dog", 43, hash, 32);
	for(i = 0; i < 32; i++) printf("%.2x", hash[i]);
	putchar('\n');

	/* 384 */
	puts("ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1");
	kripto_hash_all(kripto_hash_sha2_512, 0, "The quick brown fox jumps over the lazy dog", 43, hash, 48);
	for(i = 0; i < 48; i++) printf("%.2x", hash[i]);
	putchar('\n');

	/* 512 */
	puts("07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6");
	kripto_hash_all(kripto_hash_sha2_512, 0, "The quick brown fox jumps over the lazy dog", 43, hash, 64);
	for(i = 0; i < 64; i++) printf("%.2x", hash[i]);
	putchar('\n');

	return 0;
}
