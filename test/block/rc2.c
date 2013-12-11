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

#include <kripto/block/rc2.h>

int main(void)
{
	kripto_block *s;
	unsigned int i;
	uint8_t t[8];
	const uint8_t k[16] =
	{
		0x88, 0xBC, 0xA9, 0x0E, 0x90, 0x87, 0x5A, 0x7F,
		0x0F, 0x79, 0xC3, 0x84, 0x62, 0x7B, 0xAF, 0xB2
	};
	const uint8_t pt[8] =
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	const uint8_t ct[8] =
	{
		0x22, 0x69, 0x55, 0x2A, 0xB0, 0xF8, 0x5C, 0xA6
	};

	puts("kripto_block_rc2");

	/* 128-bit key */
	s = kripto_block_create(kripto_block_rc2, 0, k, 16);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt, t);
	for(i = 0; i < 8; i++) if(t[i] != ct[i])
	{
		puts("128-bit key encrypt: FAIL");
		break;
	}
	if(i == 8) puts("128-bit key encrypt: OK");

	kripto_block_decrypt(s, ct, t);
	for(i = 0; i < 8; i++) if(t[i] != pt[i])
	{
		puts("128-bit key decrypt: FAIL");
		break;
	}
	if(i == 8) puts("128-bit key decrypt: OK");

	kripto_block_destroy(s);

	return 0;
}
