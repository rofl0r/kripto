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
#include <kripto/hash/whirlpool.h>

int main(void)
{
	uint8_t hash[64];
	unsigned int i;

	puts("19FA61D75522A4669B44E39C1D2E1726C530232130D407F89AFEE0964997F7A73E83BE698B288FEBCF88E3E03C4F0757EA8964E59B63D93708B138CC42A66EB3");
	kripto_hash_all(kripto_hash_whirlpool, 0, "", 0, hash, 64);
	for(i = 0; i < 64; i++) printf("%.2X", hash[i]);
	putchar('\n');

	puts("DC37E008CF9EE69BF11F00ED9ABA26901DD7C28CDEC066CC6AF42E40F82F3A1E08EBA26629129D8FB7CB57211B9281A65517CC879D7B962142C65F5A7AF01467");
	kripto_hash_all(kripto_hash_whirlpool, 0, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62, hash, 64);
	for(i = 0; i < 64; i++) printf("%.2X", hash[i]);
	putchar('\n');

	return 0;
}
