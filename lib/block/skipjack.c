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

/* Based on Tom St Denis's implementation */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/memwipe.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>
#include <kripto/object/block.h>

#include <kripto/block/skipjack.h>

struct kripto_block
{
	struct kripto_block_object obj;
	uint8_t k[10];
};

static const uint8_t S[256] =
{
	0xA3, 0xD7, 0x09, 0x83, 0xF8, 0x48, 0xF6, 0xF4, 
	0xB3, 0x21, 0x15, 0x78, 0x99, 0xB1, 0xAF, 0xF9, 
	0xE7, 0x2D, 0x4D, 0x8A, 0xCE, 0x4C, 0xCA, 0x2E, 
	0x52, 0x95, 0xD9, 0x1E, 0x4E, 0x38, 0x44, 0x28, 
	0x0A, 0xDF, 0x02, 0xA0, 0x17, 0xF1, 0x60, 0x68, 
	0x12, 0xB7, 0x7A, 0xC3, 0xE9, 0xFA, 0x3D, 0x53, 
	0x96, 0x84, 0x6B, 0xBA, 0xF2, 0x63, 0x9A, 0x19, 
	0x7C, 0xAE, 0xE5, 0xF5, 0xF7, 0x16, 0x6A, 0xA2, 
	0x39, 0xB6, 0x7B, 0x0F, 0xC1, 0x93, 0x81, 0x1B, 
	0xEE, 0xB4, 0x1A, 0xEA, 0xD0, 0x91, 0x2F, 0xB8, 
	0x55, 0xB9, 0xDA, 0x85, 0x3F, 0x41, 0xBF, 0xE0, 
	0x5A, 0x58, 0x80, 0x5F, 0x66, 0x0B, 0xD8, 0x90, 
	0x35, 0xD5, 0xC0, 0xA7, 0x33, 0x06, 0x65, 0x69, 
	0x45, 0x00, 0x94, 0x56, 0x6D, 0x98, 0x9B, 0x76, 
	0x97, 0xFC, 0xB2, 0xC2, 0xB0, 0xFE, 0xDB, 0x20, 
	0xE1, 0xEB, 0xD6, 0xE4, 0xDD, 0x47, 0x4A, 0x1D, 
	0x42, 0xED, 0x9E, 0x6E, 0x49, 0x3C, 0xCD, 0x43, 
	0x27, 0xD2, 0x07, 0xD4, 0xDE, 0xC7, 0x67, 0x18, 
	0x89, 0xCB, 0x30, 0x1F, 0x8D, 0xC6, 0x8F, 0xAA, 
	0xC8, 0x74, 0xDC, 0xC9, 0x5D, 0x5C, 0x31, 0xA4, 
	0x70, 0x88, 0x61, 0x2C, 0x9F, 0x0D, 0x2B, 0x87, 
	0x50, 0x82, 0x54, 0x64, 0x26, 0x7D, 0x03, 0x40, 
	0x34, 0x4B, 0x1C, 0x73, 0xD1, 0xC4, 0xFD, 0x3B, 
	0xCC, 0xFB, 0x7F, 0xAB, 0xE6, 0x3E, 0x5B, 0xA5, 
	0xAD, 0x04, 0x23, 0x9C, 0x14, 0x51, 0x22, 0xF0, 
	0x29, 0x79, 0x71, 0x7E, 0xFF, 0x8C, 0x0E, 0xE2, 
	0x0C, 0xEF, 0xBC, 0x72, 0x75, 0x6F, 0x37, 0xA1, 
	0xEC, 0xD3, 0x8E, 0x62, 0x8B, 0x86, 0x10, 0xE8, 
	0x08, 0x77, 0x11, 0xBE, 0x92, 0x4F, 0x24, 0xC5, 
	0x32, 0x36, 0x9D, 0xCF, 0xF3, 0xA6, 0xBB, 0xAC, 
	0x5E, 0x6C, 0xA9, 0x13, 0x57, 0x25, 0xB5, 0xE3, 
	0xBD, 0xA8, 0x3A, 0x01, 0x05, 0x59, 0x2A, 0x46
};

/* i + 1 (mod 10) */
static const uint8_t plus1mod10[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};

/* i - 1 (mod 10) */
static const uint8_t minus1mod10[10] = {9, 0, 1, 2, 3, 4, 5, 6, 7, 8};

static inline uint16_t F
(
	const uint16_t x,
	const uint8_t *k,
	uint8_t *i
)
{
	uint8_t hi;
	uint8_t lo;

	hi = x >> 8;
	lo = x;

	hi ^= S[lo ^ k[*i]]; *i = plus1mod10[*i];
	lo ^= S[hi ^ k[*i]]; *i = plus1mod10[*i];
	hi ^= S[lo ^ k[*i]]; *i = plus1mod10[*i];
	lo ^= S[hi ^ k[*i]]; *i = plus1mod10[*i];

	return ((uint16_t)hi << 8) | (uint16_t)lo;
}

static inline uint16_t invF
(
	const uint16_t x,
	const uint8_t *k,
	uint8_t *i
)
{
	uint8_t hi;
	uint8_t lo;

	hi = x >> 8;
	lo = x;

	*i = minus1mod10[*i]; lo ^= S[hi ^ k[*i]];
	*i = minus1mod10[*i]; hi ^= S[lo ^ k[*i]];
	*i = minus1mod10[*i]; lo ^= S[hi ^ k[*i]];
	*i = minus1mod10[*i]; hi ^= S[lo ^ k[*i]];

	return ((uint16_t)hi << 8) | (uint16_t)lo;
}

static void skipjack_encrypt(const kripto_block *s, const void *pt, void *ct)
{
	uint16_t x0;
	uint16_t x1;
	uint16_t x2;
	uint16_t x3;
	uint16_t t0;
	uint16_t t1;

	unsigned int r = 0;
	uint8_t i = 0;

	x0 = LOAD16B(CU8(pt));
	x1 = LOAD16B(CU8(pt) + 2);
	x2 = LOAD16B(CU8(pt) + 4);
	x3 = LOAD16B(CU8(pt) + 6);

	/* RULE A */
	while(r < 8)
	{
		t0 = F(x0, s->k, &i);
		x0 = t0 ^ x3 ^ ++r;
		x3 = x2;
		x2 = x1;
		x1 = t0;
	}

	/* RULE B */
	while(r < 16)
	{
		t0 = F(x0, s->k, &i);
		t1 = x3;
		x3 = x2;
		x2 = x0 ^ x1 ^ ++r;
		x0 = t1;
		x1 = t0;
	}

	/* RULE A */
	while(r < 24)
	{
		t0 = F(x0, s->k, &i);
		x0 = t0 ^ x3 ^ ++r;
		x3 = x2;
		x2 = x1;
		x1 = t0;
	}

	/* RULE B */
	while(r < 32)
	{
		t0 = F(x0, s->k, &i);
		t1 = x3;
		x3 = x2;
		x2 = x0 ^ x1 ^ ++r;
		x0 = t1;
		x1 = t0;
	}

	STORE16B(x0, U8(ct));
	STORE16B(x1, U8(ct) + 2);
	STORE16B(x2, U8(ct) + 4);
	STORE16B(x3, U8(ct) + 6);
}

static void skipjack_decrypt(const kripto_block *s, const void *ct, void *pt)
{
	uint16_t x0;
	uint16_t x1;
	uint16_t x2;
	uint16_t x3;
	uint16_t t;

	unsigned int r = 32;
	uint8_t i = 8; /* (r * 4) % 10 */

	x0 = LOAD16B(CU8(ct));
	x1 = LOAD16B(CU8(ct) + 2);
	x2 = LOAD16B(CU8(ct) + 4);
	x3 = LOAD16B(CU8(ct) + 6);

	/* RULE B */
	while(r > 24)
	{
		t = invF(x1, s->k, &i);
		x1 = t ^ x2 ^ r--;
		x2 = x3;
		x3 = x0;
		x0 = t;
	}

	/* RULE A */
	while(r > 16)
	{
		t = x0 ^ x1 ^ r--;
		x0 = invF(x1, s->k, &i);
		x1 = x2;
		x2 = x3;
		x3 = t;
	}

	/* RULE B */
	while(r > 8)
	{
		t = invF(x1, s->k, &i);
		x1 = t ^ x2 ^ r--;
		x2 = x3;
		x3 = x0;
		x0 = t;
	}

	/* RULE A */
	while(r)
	{
		t = x0 ^ x1 ^ r--;
		x0 = invF(x1, s->k, &i);
		x1 = x2;
		x2 = x3;
		x3 = t;
	}

	STORE16B(x0, U8(pt));
	STORE16B(x1, U8(pt) + 2);
	STORE16B(x2, U8(pt) + 4);
	STORE16B(x3, U8(pt) + 6);
}

static kripto_block *skipjack_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	(void)r;

	memcpy(s->k, key, key_len);

	if(key_len < 10) memset(s->k + key_len, 0, 10 - key_len);

	return s;
}

static kripto_block *skipjack_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	s = malloc(sizeof(kripto_block));
	if(!s) return 0;

	s->obj.desc = kripto_block_skipjack;

	skipjack_recreate(s, r, key, key_len);

	return s;
}

static void skipjack_destroy(kripto_block *s)
{
	kripto_memwipe(s, sizeof(kripto_block));
	free(s);
}

static const kripto_block_desc skipjack =
{
	&skipjack_create,
	&skipjack_recreate,
	0,
	&skipjack_encrypt,
	&skipjack_decrypt,
	&skipjack_destroy,
	"Skipjack",
	8, /* block size */
	10 /* max key */
};

const kripto_block_desc *const kripto_block_skipjack = &skipjack;
