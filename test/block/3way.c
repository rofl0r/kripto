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

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <kripto/block/3way.h>

int main(void)
{
	kripto_block *s;
	uint8_t t[12];
	const uint8_t k[12] =
	{
		0xD2, 0xF0, 0x5B, 0x5E, 0xD6, 0x14,
		0x41, 0x38, 0xCA, 0xB9, 0x20, 0xCD
	};
	const uint8_t pt[12] =
	{
		0x40, 0x59, 0xC7, 0x6E, 0x83, 0xAE,
		0x9D, 0xC4, 0xAD, 0x21, 0xEC, 0xF7
	};
	const uint8_t ct[12] =
	{
		0x47, 0x8E, 0xA8, 0x71, 0x6B, 0x13,
		0xF1, 0x7C, 0x15, 0xB1, 0x55, 0xED
	};

	puts("kripto_block_3way");

	/* 96-bit key */
	s = kripto_block_create(kripto_block_3way, 0, k, 12);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt, t);
	if(memcmp(t, ct, 12)) puts("96-bit key encrypt: FAIL");
	else puts("96-bit key encrypt: OK");

	kripto_block_decrypt(s, ct, t);
	if(memcmp(t, pt, 12)) puts("96-bit key decrypt: FAIL");
	else puts("96-bit key decrypt: OK");

	kripto_block_destroy(s);

	return 0;
}
