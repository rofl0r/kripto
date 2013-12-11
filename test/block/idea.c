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

#include <kripto/block/idea.h>

int main(void)
{
	kripto_block *s;
	unsigned int i;
	uint8_t t[8];
	const uint8_t k[16] =
	{
		0x00, 0x00, 0x27, 0xED, 0x8F, 0x5C, 0x3E, 0x8B,
		0xAF, 0x16, 0x56, 0x0D, 0x14, 0xC9, 0x0B, 0x43
	};
	const uint8_t pt[8] =
	{
		0x00, 0x00, 0xAB, 0xBF, 0x94, 0xFF, 0x8B, 0x5F
	};
	const uint8_t ct[8] =
	{
		0xCB, 0xBB, 0x2E, 0x6C, 0x05, 0xEE, 0x8C, 0x89
	};

	puts("kripto_block_idea");

	/* 128-bit key */
	s = kripto_block_create(kripto_block_idea, 0, k, 16);
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
