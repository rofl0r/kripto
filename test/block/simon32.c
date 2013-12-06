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

#include <kripto/block/simon32.h>

int main(void)
{
	kripto_block *s;
	unsigned int i;
	uint8_t t[4];
	const uint8_t k[8] =
	{
		0x19, 0x18, 0x11, 0x10, 0x09, 0x08, 0x01, 0x00
	};
	const uint8_t pt[4] = {0x65, 0x65, 0x68, 0x77};
	const uint8_t ct[4] = {0xC6, 0x9B, 0xE9, 0xBB};

	puts("kripto_block_simon32");

	/* 64-bit key */
	s = kripto_block_create(kripto_block_simon32, 0, k, 8);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt, t);
	for(i = 0; i < 4; i++) if(t[i] != ct[i])
	{
		puts("64-bit key encrypt: FAIL");
		break;
	}
	if(i == 4) puts("64-bit key encrypt: OK");

	kripto_block_decrypt(s, ct, t);
	for(i = 0; i < 4; i++) if(t[i] != pt[i])
	{
		puts("64-bit key decrypt: FAIL");
		break;
	}
	if(i == 4) puts("64-bit key decrypt: OK");

	kripto_block_destroy(s);

	return 0;
}
