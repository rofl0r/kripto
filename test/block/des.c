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

#include <kripto/block/des.h>

int main(void)
{
	kripto_block *s;
	unsigned int i;
	uint8_t t[8];
	const uint8_t k[24] =
	{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67
	};
	const uint8_t pt[8] =
	{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xE7
	};
	const uint8_t ct3[8] =
	{
		0xDE, 0x0B, 0x7C, 0x06, 0xAE, 0x5E, 0x0E, 0xD5
	};

	puts("kripto_block_des");

	s = kripto_block_create(kripto_block_des, 0, k, 24);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt, t);
	for(i = 0; i < 8; i++) if(t[i] != ct3[i])
	{
		puts("192-bit key encrypt: FAIL");
		break;
	}
	if(i == 8) puts("192-bit key encrypt: OK");

	kripto_block_decrypt(s, ct3, t);
	for(i = 0; i < 8; i++) if(t[i] != pt[i])
	{
		puts("192-bit key decrypt: FAIL");
		break;
	}
	if(i == 8) puts("192-bit key decrypt: OK");

	kripto_block_destroy(s);

	return 0;
}
