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

#include <kripto/block/skipjack.h>

int main(void)
{
	kripto_block *s;
	unsigned int i;
	uint8_t t[8];
	const uint8_t k[10] =
	{
		0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
	};
	const uint8_t pt[8] =
	{
		0x33, 0x22, 0x11, 0x00, 0xDD, 0xCC, 0xBB, 0xAA
	};
	const uint8_t ct[8] =
	{
		0x25, 0x87, 0xCA, 0xE2, 0x7A, 0x12, 0xD3, 0x00
	};

	puts("kripto_block_skipjack");

	s = kripto_block_create(kripto_block_skipjack, 0, k, 10);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt, t);
	for(i = 0; i < 8; i++) if(t[i] != ct[i])
	{
		puts("encrypt: FAIL");
		break;
	}
	if(i == 8) puts("encrypt: OK");

	kripto_block_decrypt(s, ct, t);
	for(i = 0; i < 8; i++) if(t[i] != pt[i])
	{
		puts("decrypt: FAIL");
		break;
	}
	if(i == 8) puts("decrypt: OK");

	kripto_block_destroy(s);

	return 0;
}
