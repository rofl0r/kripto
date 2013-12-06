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
