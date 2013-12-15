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
#include <kripto/hash/tiger.h>

int main(void)
{
	uint8_t hash[24];
	unsigned int i;

	puts("3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3");
	kripto_hash_all(kripto_hash_tiger, 0, "", 0, hash, 24);
	for(i = 0; i < 24; i++) printf("%.2x", hash[i]);
	putchar('\n');

	puts("6d12a41e72e644f017b6f0e2f7b44c6285f06dd5d2c5b075");
	kripto_hash_all(kripto_hash_tiger, 0, "The quick brown fox jumps over the lazy dog", 43, hash, 24);
	for(i = 0; i < 24; i++) printf("%.2x", hash[i]);
	putchar('\n');

	return 0;
}
