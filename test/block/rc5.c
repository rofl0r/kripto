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

#include <kripto/block/rc5.h>

int main(void)
{
	kripto_block *s;
	uint8_t t[8];
	const uint8_t k[16] =
	{
		0x91, 0x5F, 0x46, 0x19, 0xBE, 0x41, 0xB2, 0x51,
		0x63, 0x55, 0xA5, 0x01, 0x10, 0xA9, 0xCE, 0x91
	};
	const uint8_t pt[8] =
	{
		0x21, 0xA5, 0xDB, 0xEE, 0x15, 0x4B, 0x8F, 0x6D
	};
	const uint8_t ct[8] =
	{
		0xF7, 0xC0, 0x13, 0xAC, 0x5B, 0x2B, 0x89, 0x52
	};

	puts("kripto_block_rc5");

	/* 128-bit key */
	s = kripto_block_create(kripto_block_rc5, 0, k, 16);
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
