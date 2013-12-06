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
#include <kripto/hash/md5.h>

int main(void)
{
	uint8_t hash[16];
	unsigned int i;

	puts("9e107d9d372bb6826bd81d3542a419d6");
	kripto_hash_all(kripto_hash_md5, 0, "The quick brown fox jumps over the lazy dog", 43, hash, 16);
	for(i = 0; i < 16; i++) printf("%.2x", hash[i]);
	putchar('\n');

	return 0;
}
