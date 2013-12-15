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

/* http://www.ietf.org/rfc/rfc2268.txt */

#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/rotate.h>
#include <kripto/memwipe.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>
#include <kripto/object/block.h>

#include <kripto/block/rc2.h>

struct kripto_block
{
	struct kripto_block_object obj;
	uint16_t k[64];
};

static const uint8_t sp[256] =
{
	0xD9, 0x78, 0xF9, 0xC4, 0x19, 0xDD, 0xB5, 0xED,
	0x28, 0xE9, 0xFD, 0x79, 0x4A, 0xA0, 0xD8, 0x9D,
	0xC6, 0x7E, 0x37, 0x83, 0x2B, 0x76, 0x53, 0x8E,
	0x62, 0x4C, 0x64, 0x88, 0x44, 0x8B, 0xFB, 0xA2,
	0x17, 0x9A, 0x59, 0xF5, 0x87, 0xB3, 0x4F, 0x13,
	0x61, 0x45, 0x6D, 0x8D, 0x09, 0x81, 0x7D, 0x32,
	0xBD, 0x8F, 0x40, 0xEB, 0x86, 0xB7, 0x7B, 0x0B,
	0xF0, 0x95, 0x21, 0x22, 0x5C, 0x6B, 0x4E, 0x82,
	0x54, 0xD6, 0x65, 0x93, 0xCE, 0x60, 0xB2, 0x1C,
	0x73, 0x56, 0xC0, 0x14, 0xA7, 0x8C, 0xF1, 0xDC,
	0x12, 0x75, 0xCA, 0x1F, 0x3B, 0xBE, 0xE4, 0xD1,
	0x42, 0x3D, 0xD4, 0x30, 0xA3, 0x3C, 0xB6, 0x26,
	0x6F, 0xBF, 0x0E, 0xDA, 0x46, 0x69, 0x07, 0x57,
	0x27, 0xF2, 0x1D, 0x9B, 0xBC, 0x94, 0x43, 0x03,
	0xF8, 0x11, 0xC7, 0xF6, 0x90, 0xEF, 0x3E, 0xE7,
	0x06, 0xC3, 0xD5, 0x2F, 0xC8, 0x66, 0x1E, 0xD7,
	0x08, 0xE8, 0xEA, 0xDE, 0x80, 0x52, 0xEE, 0xF7,
	0x84, 0xAA, 0x72, 0xAC, 0x35, 0x4D, 0x6A, 0x2A,
	0x96, 0x1A, 0xD2, 0x71, 0x5A, 0x15, 0x49, 0x74,
	0x4B, 0x9F, 0xD0, 0x5E, 0x04, 0x18, 0xA4, 0xEC,
	0xC2, 0xE0, 0x41, 0x6E, 0x0F, 0x51, 0xCB, 0xCC,
	0x24, 0x91, 0xAF, 0x50, 0xA1, 0xF4, 0x70, 0x39,
	0x99, 0x7C, 0x3A, 0x85, 0x23, 0xB8, 0xB4, 0x7A,
	0xFC, 0x02, 0x36, 0x5B, 0x25, 0x55, 0x97, 0x31,
	0x2D, 0x5D, 0xFA, 0x98, 0xE3, 0x8A, 0x92, 0xAE,
	0x05, 0xDF, 0x29, 0x10, 0x67, 0x6C, 0xBA, 0xC9,
	0xD3, 0x00, 0xE6, 0xCF, 0xE1, 0x9E, 0xA8, 0x2C,
	0x63, 0x16, 0x01, 0x3F, 0x58, 0xE2, 0x89, 0xA9,
	0x0D, 0x38, 0x34, 0x1B, 0xAB, 0x33, 0xFF, 0xB0,
	0xBB, 0x48, 0x0C, 0x5F, 0xB9, 0xB1, 0xCD, 0x2E,
	0xC5, 0xF3, 0xDB, 0x47, 0xE5, 0xA5, 0x9C, 0x77,
	0x0A, 0xA6, 0x20, 0x68, 0xFE, 0x7F, 0xC1, 0xAD
};

static kripto_block *rc2_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	int i;
	uint8_t t[128];
	unsigned int t8;

	(void)r;

	memcpy(t, key, key_len);

	for(i = key_len; i < 128; i++)
		t[i] = sp[(uint8_t)(t[i - 1] + t[i - key_len])];

	t8 = ((key_len << 3) + 7) >> 3;

	t[128 - t8] = sp[t[128 - t8] & (0xFF >> (7 & -(key_len << 3)))];

	for(i = 127 - t8; i >= 0; i--) t[i] = sp[t[i + 1] ^ t[i + t8]];

	for(i = 0; i < 64; i++) s->k[i] = LOAD16L(t + (i << 1));

	kripto_memwipe(t, 128);

	return s;
}

static void rc2_encrypt(const kripto_block *s, const void *pt, void *ct)
{
	uint16_t x0;
	uint16_t x1;
	uint16_t x2;
	uint16_t x3;
	unsigned int i;

	x0 = LOAD16L(CU8(pt));
	x1 = LOAD16L(CU8(pt) + 2);
	x2 = LOAD16L(CU8(pt) + 4);
	x3 = LOAD16L(CU8(pt) + 6);

	for(i = 0; i < 16; i++)
	{
		x0 += (x1 & ~x3) + (x2 & x3) + s->k[i << 2];
		x0 = ROL16_01(x0);

		x1 += (x2 & ~x0) + (x3 & x0) + s->k[(i << 2) + 1];
		x1 = ROL16_02(x1);

		x2 += (x3 & ~x1) + (x0 & x1) + s->k[(i << 2) + 2];
		x2 = ROL16_03(x2);

		x3 += (x0 & ~x2) + (x1 & x2) + s->k[(i << 2) + 3];
		x3 = ROL16_05(x3);

		if(i == 4 || i == 10)
		{
			x0 += s->k[x3 & 63];
			x1 += s->k[x0 & 63];
			x2 += s->k[x1 & 63];
			x3 += s->k[x2 & 63];
		}
	}

	STORE16L(x0, U8(ct));
	STORE16L(x1, U8(ct) + 2);
	STORE16L(x2, U8(ct) + 4);
	STORE16L(x3, U8(ct) + 6);
}

static void rc2_decrypt(const kripto_block *s, const void *ct, void *pt)
{
	uint16_t x0;
	uint16_t x1;
	uint16_t x2;
	uint16_t x3;
	int i;

	x0 = LOAD16L(CU8(ct));
	x1 = LOAD16L(CU8(ct) + 2);
	x2 = LOAD16L(CU8(ct) + 4);
	x3 = LOAD16L(CU8(ct) + 6);

	for(i = 15; i >= 0; i--)
	{
		if(i == 4 || i == 10)
		{
			x3 -= s->k[x2 & 63];
			x2 -= s->k[x1 & 63];
			x1 -= s->k[x0 & 63];
			x0 -= s->k[x3 & 63];
		}

		x3 = ROR16_05(x3);
		x3 -= (x0 & ~x2) + (x1 & x2) + s->k[(i << 2) + 3];

		x2 = ROR16_03(x2);
		x2 -= (x3 & ~x1) + (x0 & x1) + s->k[(i << 2) + 2];

		x1 = ROR16_02(x1);
		x1 -= (x2 & ~x0) + (x3 & x0) + s->k[(i << 2) + 1];

		x0 = ROR16_01(x0);
		x0 -= (x1 & ~x3) + (x2 & x3) + s->k[i << 2];
	}

	STORE16L(x0, U8(pt));
	STORE16L(x1, U8(pt) + 2);
	STORE16L(x2, U8(pt) + 4);
	STORE16L(x3, U8(pt) + 6);
}

static kripto_block *rc2_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	s = malloc(sizeof(kripto_block));
	if(!s) return 0;

	s->obj.desc = kripto_block_rc2;

	return rc2_recreate(s, r, key, key_len);
}

static void rc2_destroy(kripto_block *s)
{
	kripto_memwipe(s, sizeof(kripto_block));
	free(s);
}

static const kripto_block_desc rc2 =
{
	&rc2_create,
	&rc2_recreate,
	0,
	&rc2_encrypt,
	&rc2_decrypt,
	&rc2_destroy,
	8, /* block size */
	128 /* max key */
};

const kripto_block_desc *const kripto_block_rc2 = &rc2;
