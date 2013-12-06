/*
 * Written in 2013 by Gregor Pintar <grpintar@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated
 * all copyright and related and neighboring rights to this software
 * to the public domain worldwide.
 * 
 * This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication.
 * If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <kripto/hash.h>
#include <kripto/hash/blake256.h>

int main(void)
{
	uint8_t hash[32];
	unsigned int i;

	/* 224 */
	puts("4504cb0314fb2a4f7a692e696e487912fe3f2468fe312c73a5278ec5");
	kripto_hash_all(kripto_hash_blake256, 0, "\x0", 1, hash, 28);
	for(i = 0; i < 28; i++) printf("%.2x", hash[i]);
	putchar('\n');

	/* 256 */
	puts("7576698ee9cad30173080678e5965916adbb11cb5245d386bf1ffda1cb26c9d7");
	kripto_hash_all(kripto_hash_blake256, 0, "The quick brown fox jumps over the lazy dog", 43, hash, 32);
	for(i = 0; i < 32; i++) printf("%.2x", hash[i]);
	putchar('\n');

	puts("0ce8d4ef4dd7cd8d62dfded9d4edb0a774ae6a41929a74da23109e8f11139c87");
	kripto_hash_all(kripto_hash_blake256, 0, "\x0", 1, hash, 32);
	for(i = 0; i < 32; i++) printf("%.2x", hash[i]);
	putchar('\n');

	return 0;
}
