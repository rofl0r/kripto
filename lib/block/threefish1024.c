/*
 * Copyright (C) 2013 Gregor Pintar <grpintar@gmail.com>
 *
 * Permission is granted to deal in this work without any restriction,
 * including unlimited rights to use, publicly perform, publish,
 * reproduce, relicence, modify, merge, and/or distribute in any form,
 * for any purpose, with or without fee, and by any means.
 *
 * This work is provided "AS IS" and WITHOUT WARRANTY of any kind,
 * to the utmost extent permitted by applicable law. In no event
 * shall a licensor, author or contributor be held liable for any
 * issues arising in any way out of dealing in the work.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <kripto/macros.h>
#include <kripto/memwipe.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>

#include <kripto/block/threefish1024.h>

#define C240 0x1BD11BDAA9FC1A22

struct kripto_block
{
	const kripto_block_desc *desc;
	unsigned int rounds;
	uint64_t t[3];
	uint64_t k[17];
};

static void threefish1024_tweak
(
	kripto_block *s,
	const void *tweak,
	unsigned int len
)
{
	(void)len;

	s->t[0] = U8TO64_LE(CU8(tweak));
	s->t[1] = U8TO64_LE(CU8(tweak) + 8);
	s->t[2] = s->t[0] ^ s->t[1];
}

static void threefish1024_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint64_t x0 = U8TO64_LE(CU8(pt)) + s->k[0];
	uint64_t x1 = U8TO64_LE(CU8(pt) + 8) + s->k[1];
	uint64_t x2 = U8TO64_LE(CU8(pt) + 16) + s->k[2];
	uint64_t x3 = U8TO64_LE(CU8(pt) + 24) + s->k[3];
	uint64_t x4 = U8TO64_LE(CU8(pt) + 32) + s->k[4];
	uint64_t x5 = U8TO64_LE(CU8(pt) + 40) + s->k[5];
	uint64_t x6 = U8TO64_LE(CU8(pt) + 48) + s->k[6];
	uint64_t x7 = U8TO64_LE(CU8(pt) + 56) + s->k[7];
	uint64_t x8 = U8TO64_LE(CU8(pt) + 64) + s->k[8];
	uint64_t x9 = U8TO64_LE(CU8(pt) + 72) + s->k[9];
	uint64_t x10 = U8TO64_LE(CU8(pt) + 80) + s->k[10];
	uint64_t x11 = U8TO64_LE(CU8(pt) + 88) + s->k[11];
	uint64_t x12 = U8TO64_LE(CU8(pt) + 96) + s->k[12];
	uint64_t x13 = U8TO64_LE(CU8(pt) + 104) + s->k[13] + s->t[0];
	uint64_t x14 = U8TO64_LE(CU8(pt) + 112) + s->k[14] + s->t[1];
	uint64_t x15 = U8TO64_LE(CU8(pt) + 120) + s->k[15];
	unsigned int r = 1;

	while(r <= s->rounds >> 2)
	{
		x0 += x1; x1 = ROL64(x1, 24); x1 ^= x0;
		x2 += x3; x3 = ROL64(x3, 13); x3 ^= x2;
		x4 += x5; x5 = ROL64(x5, 8); x5 ^= x4;
		x6 += x7; x7 = ROL64(x7, 47); x7 ^= x6;
		x8 += x9; x9 = ROL64(x9, 8); x9 ^= x8;
		x10 += x11; x11 = ROL64(x11, 17); x11 ^= x10;
		x12 += x13; x13 = ROL64(x13, 22); x13 ^= x12;
		x14 += x15; x15 = ROL64(x15, 37); x15 ^= x14;

		x0 += x9; x9 = ROL64(x9, 38); x9 ^= x0;
		x2 += x13; x13 = ROL64(x13, 19); x13 ^= x2;
		x6 += x11; x11 = ROL64(x11, 10); x11 ^= x6;
		x4 += x15; x15 = ROL64(x15, 55); x15 ^= x4;
		x10 += x7; x7 = ROL64(x7, 49); x7 ^= x10;
		x12 += x3; x3 = ROL64(x3, 18); x3 ^= x12;
		x14 += x5; x5 = ROL64(x5, 23); x5 ^= x14;
		x8 += x1; x1 = ROL64(x1, 52); x1 ^= x8;

		x0 += x7; x7 = ROL64(x7, 33); x7 ^= x0;
		x2 += x5; x5 = ROL64(x5, 4); x5 ^= x2;
		x4 += x3; x3 = ROL64(x3, 51); x3 ^= x4;
		x6 += x1; x1 = ROL64(x1, 13); x1 ^= x6;
		x12 += x15; x15 = ROL64(x15, 34); x15 ^= x12;
		x14 += x13; x13 = ROL64(x13, 41); x13 ^= x14;
		x8 += x11; x11 = ROL64(x11, 59); x11 ^= x8;
		x10 += x9; x9 = ROL64(x9, 17); x9 ^= x10;

		x0 += x15; x15 = ROL64(x15, 5); x15 ^= x0;
		x2 += x11; x11 = ROL64(x11, 20); x11 ^= x2;
		x6 += x13; x13 = ROL64(x13, 48); x13 ^= x6;
		x4 += x9; x9 = ROL64(x9, 41); x9 ^= x4;
		x14 += x1; x1 = ROL64(x1, 47); x1 ^= x14;
		x8 += x5; x5 = ROL64(x5, 28); x5 ^= x8;
		x10 += x3; x3 = ROL64(x3, 16); x3 ^= x10;
		x12 += x7; x7 = ROL64(x7, 25); x7 ^= x12;

		x0 += s->k[r % 17];
		x1 += s->k[(r + 1) % 17];
		x2 += s->k[(r + 2) % 17];
		x3 += s->k[(r + 3) % 17];
		x4 += s->k[(r + 4) % 17];
		x5 += s->k[(r + 5) % 17];
		x6 += s->k[(r + 6) % 17];
		x7 += s->k[(r + 7) % 17];
		x8 += s->k[(r + 8) % 17];
		x9 += s->k[(r + 9) % 17];
		x10 += s->k[(r + 10) % 17];
		x11 += s->k[(r + 11) % 17];
		x12 += s->k[(r + 12) % 17];
		x13 += s->k[(r + 13) % 17] + s->t[r % 3];
		x14 += s->k[(r + 14) % 17] + s->t[(r + 1) % 3];
		x15 += s->k[(r + 15) % 17] + r;
		r++;

		x0 += x1; x1 = ROL64(x1, 41); x1 ^= x0;
		x2 += x3; x3 = ROL64(x3, 9); x3 ^= x2;
		x4 += x5; x5 = ROL64(x5, 37); x5 ^= x4;
		x6 += x7; x7 = ROL64(x7, 31); x7 ^= x6;
		x8 += x9; x9 = ROL64(x9, 12); x9 ^= x8;
		x10 += x11; x11 = ROL64(x11, 47); x11 ^= x10;
		x12 += x13; x13 = ROL64(x13, 44); x13 ^= x12;
		x14 += x15; x15 = ROL64(x15, 30); x15 ^= x14;

		x0 += x9; x9 = ROL64(x9, 16); x9 ^= x0;
		x2 += x13; x13 = ROL64(x13, 34); x13 ^= x2;
		x6 += x11; x11 = ROL64(x11, 56); x11 ^= x6;
		x4 += x15; x15 = ROL64(x15, 51); x15 ^= x4;
		x10 += x7; x7 = ROL64(x7, 4); x7 ^= x10;
		x12 += x3; x3 = ROL64(x3, 53); x3 ^= x12;
		x14 += x5; x5 = ROL64(x5, 42); x5 ^= x14;
		x8 += x1; x1 = ROL64(x1, 41); x1 ^= x8;

		x0 += x7; x7 = ROL64(x7, 31); x7 ^= x0;
		x2 += x5; x5 = ROL64(x5, 44); x5 ^= x2;
		x4 += x3; x3 = ROL64(x3, 47); x3 ^= x4;
		x6 += x1; x1 = ROL64(x1, 46); x1 ^= x6;
		x12 += x15; x15 = ROL64(x15, 19); x15 ^= x12;
		x14 += x13; x13 = ROL64(x13, 42); x13 ^= x14;
		x8 += x11; x11 = ROL64(x11, 44); x11 ^= x8;
		x10 += x9; x9 = ROL64(x9, 25); x9 ^= x10;

		x0 += x15; x15 = ROL64(x15, 9); x15 ^= x0;
		x2 += x11; x11 = ROL64(x11, 48); x11 ^= x2;
		x6 += x13; x13 = ROL64(x13, 35); x13 ^= x6;
		x4 += x9; x9 = ROL64(x9, 52); x9 ^= x4;
		x14 += x1; x1 = ROL64(x1, 23); x1 ^= x14;
		x8 += x5; x5 = ROL64(x5, 31); x5 ^= x8;
		x10 += x3; x3 = ROL64(x3, 37); x3 ^= x10;
		x12 += x7; x7 = ROL64(x7, 20); x7 ^= x12;

		x0 += s->k[r % 17];
		x1 += s->k[(r + 1) % 17];
		x2 += s->k[(r + 2) % 17];
		x3 += s->k[(r + 3) % 17];
		x4 += s->k[(r + 4) % 17];
		x5 += s->k[(r + 5) % 17];
		x6 += s->k[(r + 6) % 17];
		x7 += s->k[(r + 7) % 17];
		x8 += s->k[(r + 8) % 17];
		x9 += s->k[(r + 9) % 17];
		x10 += s->k[(r + 10) % 17];
		x11 += s->k[(r + 11) % 17];
		x12 += s->k[(r + 12) % 17];
		x13 += s->k[(r + 13) % 17] + s->t[r % 3];
		x14 += s->k[(r + 14) % 17] + s->t[(r + 1) % 3];
		x15 += s->k[(r + 15) % 17] + r;
		r++;
	}

	U64TO8_LE(x0, U8(ct));
	U64TO8_LE(x1, U8(ct) + 8);
	U64TO8_LE(x2, U8(ct) + 16);
	U64TO8_LE(x3, U8(ct) + 24);
	U64TO8_LE(x4, U8(ct) + 32);
	U64TO8_LE(x5, U8(ct) + 40);
	U64TO8_LE(x6, U8(ct) + 48);
	U64TO8_LE(x7, U8(ct) + 56);
	U64TO8_LE(x8, U8(ct) + 64);
	U64TO8_LE(x9, U8(ct) + 72);
	U64TO8_LE(x10, U8(ct) + 80);
	U64TO8_LE(x11, U8(ct) + 88);
	U64TO8_LE(x12, U8(ct) + 96);
	U64TO8_LE(x13, U8(ct) + 104);
	U64TO8_LE(x14, U8(ct) + 112);
	U64TO8_LE(x15, U8(ct) + 120);
}

static void threefish1024_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint64_t x0 = U8TO64_LE(CU8(ct));
	uint64_t x1 = U8TO64_LE(CU8(ct) + 8);
	uint64_t x2 = U8TO64_LE(CU8(ct) + 16);
	uint64_t x3 = U8TO64_LE(CU8(ct) + 24);
	uint64_t x4 = U8TO64_LE(CU8(ct) + 32);
	uint64_t x5 = U8TO64_LE(CU8(ct) + 40);
	uint64_t x6 = U8TO64_LE(CU8(ct) + 48);
	uint64_t x7 = U8TO64_LE(CU8(ct) + 56);
	uint64_t x8 = U8TO64_LE(CU8(ct) + 64);
	uint64_t x9 = U8TO64_LE(CU8(ct) + 72);
	uint64_t x10 = U8TO64_LE(CU8(ct) + 80);
	uint64_t x11 = U8TO64_LE(CU8(ct) + 88);
	uint64_t x12 = U8TO64_LE(CU8(ct) + 96);
	uint64_t x13 = U8TO64_LE(CU8(ct) + 104);
	uint64_t x14 = U8TO64_LE(CU8(ct) + 112);
	uint64_t x15 = U8TO64_LE(CU8(ct) + 120);
	unsigned int r = s->rounds >> 2;

	while(r > 1)
	{
		x0 -= s->k[r % 17];
		x1 -= s->k[(r + 1) % 17];
		x2 -= s->k[(r + 2) % 17];
		x3 -= s->k[(r + 3) % 17];
		x4 -= s->k[(r + 4) % 17];
		x5 -= s->k[(r + 5) % 17];
		x6 -= s->k[(r + 6) % 17];
		x7 -= s->k[(r + 7) % 17];
		x8 -= s->k[(r + 8) % 17];
		x9 -= s->k[(r + 9) % 17];
		x10 -= s->k[(r + 10) % 17];
		x11 -= s->k[(r + 11) % 17];
		x12 -= s->k[(r + 12) % 17];
		x13 -= s->k[(r + 13) % 17] + s->t[r % 3];
		x14 -= s->k[(r + 14) % 17] + s->t[(r + 1) % 3];
		x15 -= s->k[(r + 15) % 17] + r;
		r--;

		x7 = ROR64(x7 ^ x12, 20); x12 -= x7;
		x3 = ROR64(x3 ^ x10, 37); x10 -= x3;
		x5 = ROR64(x5 ^ x8, 31); x8 -= x5;
		x1 = ROR64(x1 ^ x14, 23); x14 -= x1;
		x9 = ROR64(x9 ^ x4, 52); x4 -= x9;
		x13 = ROR64(x13 ^ x6, 35); x6 -= x13;
		x11 = ROR64(x11 ^ x2, 48); x2 -= x11;
		x15 = ROR64(x15 ^ x0, 9); x0 -= x15;

		x9 = ROR64(x9 ^ x10, 25); x10 -= x9;
		x11 = ROR64(x11 ^ x8, 44); x8 -= x11;
		x13 = ROR64(x13 ^ x14, 42); x14 -= x13;
		x15 = ROR64(x15 ^ x12, 19); x12 -= x15;
		x1 = ROR64(x1 ^ x6, 46); x6 -= x1;
		x3 = ROR64(x3 ^ x4, 47); x4 -= x3;
		x5 = ROR64(x5 ^ x2, 44); x2 -= x5;
		x7 = ROR64(x7 ^ x0, 31); x0 -= x7;

		x1 = ROR64(x1 ^ x8, 41); x8 -= x1;
		x5 = ROR64(x5 ^ x14, 42); x14 -= x5;
		x3 = ROR64(x3 ^ x12, 53); x12 -= x3;
		x7 = ROR64(x7 ^ x10, 4); x10 -= x7;
		x15 = ROR64(x15 ^ x4, 51); x4 -= x15;
		x11 = ROR64(x11 ^ x6, 56); x6 -= x11;
		x13 = ROR64(x13 ^ x2, 34); x2 -= x13;
		x9 = ROR64(x9 ^ x0, 16); x0 -= x9;

		x15 = ROR64(x15 ^ x14, 30); x14 -= x15;
		x13 = ROR64(x13 ^ x12, 44); x12 -= x13;
		x11 = ROR64(x11 ^ x10, 47); x10 -= x11;
		x9 = ROR64(x9 ^ x8, 12); x8 -= x9;
		x7 = ROR64(x7 ^ x6, 31); x6 -= x7;
		x5 = ROR64(x5 ^ x4, 37); x4 -= x5;
		x3 = ROR64(x3 ^ x2, 9); x2 -= x3;
		x1 = ROR64(x1 ^ x0, 41); x0 -= x1;

		x0 -= s->k[r % 17];
		x1 -= s->k[(r + 1) % 17];
		x2 -= s->k[(r + 2) % 17];
		x3 -= s->k[(r + 3) % 17];
		x4 -= s->k[(r + 4) % 17];
		x5 -= s->k[(r + 5) % 17];
		x6 -= s->k[(r + 6) % 17];
		x7 -= s->k[(r + 7) % 17];
		x8 -= s->k[(r + 8) % 17];
		x9 -= s->k[(r + 9) % 17];
		x10 -= s->k[(r + 10) % 17];
		x11 -= s->k[(r + 11) % 17];
		x12 -= s->k[(r + 12) % 17];
		x13 -= s->k[(r + 13) % 17] + s->t[r % 3];
		x14 -= s->k[(r + 14) % 17] + s->t[(r + 1) % 3];
		x15 -= s->k[(r + 15) % 17] + r;
		r--;

		x7 = ROR64(x7 ^ x12, 25); x12 -= x7;
		x3 = ROR64(x3 ^ x10, 16); x10 -= x3;
		x5 = ROR64(x5 ^ x8, 28); x8 -= x5;
		x1 = ROR64(x1 ^ x14, 47); x14 -= x1;
		x9 = ROR64(x9 ^ x4, 41); x4 -= x9;
		x13 = ROR64(x13 ^ x6, 48); x6 -= x13;
		x11 = ROR64(x11 ^ x2, 20); x2 -= x11;
		x15 = ROR64(x15 ^ x0, 5); x0 -= x15;

		x9 = ROR64(x9 ^ x10, 17); x10 -= x9;
		x11 = ROR64(x11 ^ x8, 59); x8 -= x11;
		x13 = ROR64(x13 ^ x14, 41); x14 -= x13;
		x15 = ROR64(x15 ^ x12, 34); x12 -= x15;
		x1 = ROR64(x1 ^ x6, 13); x6 -= x1;
		x3 = ROR64(x3 ^ x4, 51); x4 -= x3;
		x5 = ROR64(x5 ^ x2, 4); x2 -= x5;
		x7 = ROR64(x7 ^ x0, 33); x0 -= x7;

		x1 = ROR64(x1 ^ x8, 52); x8 -= x1;
		x5 = ROR64(x5 ^ x14, 23); x14 -= x5;
		x3 = ROR64(x3 ^ x12, 18); x12 -= x3;
		x7 = ROR64(x7 ^ x10, 49); x10 -= x7;
		x15 = ROR64(x15 ^ x4, 55); x4 -= x15;
		x11 = ROR64(x11 ^ x6, 10); x6 -= x11;
		x13 = ROR64(x13 ^ x2, 19); x2 -= x13;
		x9 = ROR64(x9 ^ x0, 38); x0 -= x9;

		x15 = ROR64(x15 ^ x14, 37); x14 -= x15;
		x13 = ROR64(x13 ^ x12, 22); x12 -= x13;
		x11 = ROR64(x11 ^ x10, 17); x10 -= x11;
		x9 = ROR64(x9 ^ x8, 8); x8 -= x9;
		x7 = ROR64(x7 ^ x6, 47); x6 -= x7;
		x5 = ROR64(x5 ^ x4, 8); x4 -= x5;
		x3 = ROR64(x3 ^ x2, 13); x2 -= x3;
		x1 = ROR64(x1 ^ x0, 24); x0 -= x1;
	}

	x0 -= s->k[0];
	x1 -= s->k[1];
	x2 -= s->k[2];
	x3 -= s->k[3];
	x4 -= s->k[4];
	x5 -= s->k[5];
	x6 -= s->k[6];
	x7 -= s->k[7];
	x8 -= s->k[8];
	x9 -= s->k[9];
	x10 -= s->k[10];
	x11 -= s->k[11];
	x12 -= s->k[12];
	x13 -= s->k[13] + s->t[0];
	x14 -= s->k[14] + s->t[1];
	x15 -= s->k[15];

	U64TO8_LE(x0, U8(pt));
	U64TO8_LE(x1, U8(pt) + 8);
	U64TO8_LE(x2, U8(pt) + 16);
	U64TO8_LE(x3, U8(pt) + 24);
	U64TO8_LE(x4, U8(pt) + 32);
	U64TO8_LE(x5, U8(pt) + 40);
	U64TO8_LE(x6, U8(pt) + 48);
	U64TO8_LE(x7, U8(pt) + 56);
	U64TO8_LE(x8, U8(pt) + 64);
	U64TO8_LE(x9, U8(pt) + 72);
	U64TO8_LE(x10, U8(pt) + 80);
	U64TO8_LE(x11, U8(pt) + 88);
	U64TO8_LE(x12, U8(pt) + 96);
	U64TO8_LE(x13, U8(pt) + 104);
	U64TO8_LE(x14, U8(pt) + 112);
	U64TO8_LE(x15, U8(pt) + 120);
}

static kripto_block *threefish1024_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	unsigned int i;

	s->rounds = r;
	if(!s->rounds) s->rounds = 80;

	memset(s->k, 0, 128);

	for(i = key_len - 1; i != UINT_MAX; i--)
		s->k[i >> 3] = (s->k[i >> 3] << 8) | CU8(key)[i];

	s->k[16] = s->k[0] ^ s->k[1] ^ s->k[2] ^ s->k[3]
		^ s->k[4] ^ s->k[5] ^ s->k[6] ^ s->k[7]
		^ s->k[8] ^ s->k[9] ^ s->k[10] ^ s->k[11]
		^ s->k[12] ^ s->k[13] ^ s->k[14] ^ s->k[15] ^ C240;

	s->t[0] = s->t[1] = s->t[2] = 0;

	return s;
}

static kripto_block *threefish1024_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	s = malloc(sizeof(kripto_block));
	if(!s) return 0;

	s->desc = kripto_block_threefish1024;

	(void)threefish1024_recreate(s, r, key, key_len);

	return s;
}

static void threefish1024_destroy(kripto_block *s)
{
	kripto_memwipe(s, sizeof(kripto_block));
	free(s);
}

static const kripto_block_desc threefish1024 =
{
	&threefish1024_create,
	&threefish1024_recreate,
	&threefish1024_tweak,
	&threefish1024_encrypt,
	&threefish1024_decrypt,
	&threefish1024_destroy,
	128, /* block size */
	128 /* max key */
};

const kripto_block_desc *const kripto_block_threefish1024 = &threefish1024;
