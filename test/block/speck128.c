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

#include <kripto/block/speck128.h>

int main(void)
{
	kripto_block *s;
	unsigned int i;
	uint8_t t[16];
	const uint8_t k[32] =
	{
		0x1F, 0x1E, 0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18,
		0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
		0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
		0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
	};
	const uint8_t pt128[16] =
	{
		0x6C, 0x61, 0x76, 0x69, 0x75, 0x71, 0x65, 0x20,
		0x74, 0x69, 0x20, 0x65, 0x64, 0x61, 0x6D, 0x20
	};
	const uint8_t pt192[16] =
	{
		0x72, 0x61, 0x48, 0x20, 0x66, 0x65, 0x69, 0x68,
		0x43, 0x20, 0x6F, 0x74, 0x20, 0x74, 0x6E, 0x65
	};
	const uint8_t pt256[16] =
	{
		0x65, 0x73, 0x6F, 0x68, 0x74, 0x20, 0x6E, 0x49,
		0x20, 0x2E, 0x72, 0x65, 0x6E, 0x6F, 0x6F, 0x70
	};
	const uint8_t ct128[16] =
	{
		0xA6, 0x5D, 0x98, 0x51, 0x79, 0x78, 0x32, 0x65,
		0x78, 0x60, 0xFE, 0xDF, 0x5C, 0x57, 0x0D, 0x18
	};
	const uint8_t ct192[16] =
	{
		0x1B, 0xE4, 0xCF, 0x3A, 0x13, 0x13, 0x55, 0x66,
		0xF9, 0xBC, 0x18, 0x5D, 0xE0, 0x3C, 0x18, 0x86
	};
	const uint8_t ct256[16] =
	{
		0x41, 0x09, 0x01, 0x04, 0x05, 0xC0, 0xF5, 0x3E,
		0x4E, 0xEE, 0xB4, 0x8D, 0x9C, 0x18, 0x8F, 0x43
	};

	puts("kripto_block_speck128");

	/* 128-bit key */
	s = kripto_block_create(kripto_block_speck128, 0, k + 16, 16);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt128, t);
	for(i = 0; i < 16; i++) if(t[i] != ct128[i])
	{
		puts("128-bit key encrypt: FAIL");
		break;
	}
	if(i == 16) puts("128-bit key encrypt: OK");

	kripto_block_decrypt(s, ct128, t);
	for(i = 0; i < 16; i++) if(t[i] != pt128[i])
	{
		puts("128-bit key decrypt: FAIL");
		break;
	}
	if(i == 16) puts("128-bit key decrypt: OK");

	/* 192-bit key */
	s = kripto_block_recreate(s, 0, k + 8, 24);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt192, t);
	for(i = 0; i < 16; i++) if(t[i] != ct192[i])
	{
		puts("192-bit key encrypt: FAIL");
		break;
	}
	if(i == 16) puts("192-bit key encrypt: OK");

	kripto_block_decrypt(s, ct192, t);
	for(i = 0; i < 16; i++) if(t[i] != pt192[i])
	{
		puts("192-bit key decrypt: FAIL");
		break;
	}
	if(i == 16) puts("192-bit key decrypt: OK");

	/* 256-bit key */
	s = kripto_block_recreate(s, 0, k, 32);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt256, t);
	for(i = 0; i < 16; i++) if(t[i] != ct256[i])
	{
		puts("256-bit key encrypt: FAIL");
		break;
	}
	if(i == 16) puts("256-bit key encrypt: OK");

	kripto_block_decrypt(s, ct256, t);
	for(i = 0; i < 16; i++) if(t[i] != pt256[i])
	{
		puts("256-bit key decrypt: FAIL");
		break;
	}
	if(i == 16) puts("256-bit key decrypt: OK");

	kripto_block_destroy(s);

	return 0;
}
