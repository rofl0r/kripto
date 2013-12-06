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
