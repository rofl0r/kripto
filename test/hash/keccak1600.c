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
#include <kripto/hash/keccak1600.h>

int main(void)
{
	uint8_t hash[64] = {0xC6, 0xF5, 0x0B, 0xB7, 0x4E, 0x29};
	unsigned int i;

	puts("923062c4e6f057597220d182dbb10e81cd25f60b54005b2a75dd33d6dac518d0");
	kripto_hash_all(kripto_hash_keccak1600, 0, hash, 6, hash, 32);
	for(i = 0; i < 32; i++) printf("%.2x", hash[i]);
	putchar('\n');

	/* 224 */
	puts("310aee6b30c47350576ac2873fa89fd190cdc488442f3ef654cf23fe");
	kripto_hash_all(kripto_hash_keccak1600, 0, "The quick brown fox jumps over the lazy dog", 43, hash, 28);
	for(i = 0; i < 28; i++) printf("%.2x", hash[i]);
	putchar('\n');

	/* 256 */
	puts("4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15");
	kripto_hash_all(kripto_hash_keccak1600, 0, "The quick brown fox jumps over the lazy dog", 43, hash, 32);
	for(i = 0; i < 32; i++) printf("%.2x", hash[i]);
	putchar('\n');

	/* 384 */
	puts("283990fa9d5fb731d786c5bbee94ea4db4910f18c62c03d173fc0a5e494422e8a0b3da7574dae7fa0baf005e504063b3");
	kripto_hash_all(kripto_hash_keccak1600, 0, "The quick brown fox jumps over the lazy dog", 43, hash, 48);
	for(i = 0; i < 48; i++) printf("%.2x", hash[i]);
	putchar('\n');

	/* 512 */
	puts("d135bb84d0439dbac432247ee573a23ea7d3c9deb2a968eb31d47c4fb45f1ef4422d6c531b5b9bd6f449ebcc449ea94d0a8f05f62130fda612da53c79659f609");
	kripto_hash_all(kripto_hash_keccak1600, 0, "The quick brown fox jumps over the lazy dog", 43, hash, 64);
	for(i = 0; i < 64; i++) printf("%.2x", hash[i]);
	putchar('\n');

	return 0;
}
