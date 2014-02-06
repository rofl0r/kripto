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

#include <kripto/block.h>
#include <kripto/block/khazad.h>

int main(void)
{
	kripto_block *s;
	uint8_t t[8];
	const uint8_t k[16] =
	{
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	const uint8_t pt[8] =
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	const uint8_t ct[8] =
	{
		0x49, 0xA4, 0xCE, 0x32, 0xAC, 0x19, 0x0E, 0x3F
	};

	puts("kripto_block_khazad");

	/* 128-bit key */
	s = kripto_block_create(kripto_block_khazad, 0, k, 16);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt, t);
	if(memcmp(t, ct, 8)) puts("128-bit key encrypt: FAIL");
	else puts("128-bit key encrypt: OK");

	kripto_block_decrypt(s, ct, t);
	if(memcmp(t, pt, 8)) puts("128-bit key decrypt: FAIL");
	else puts("128-bit key decrypt: OK");

	kripto_block_destroy(s);

	return 0;
}
