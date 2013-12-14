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
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/rotate.h>
#include <kripto/memwipe.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>
#include <kripto/object/block.h>

#include <kripto/block/threefish1024.h>

#define C240 0x1BD11BDAA9FC1A22

struct kripto_block
{
	struct kripto_block_object obj;
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
	s->t[0] = s->t[1] = 0;

	while(--len != UINT_MAX)
		s->t[len >> 3] = (s->t[len >> 3] << 8) | CU8(tweak)[len];

	s->t[2] = s->t[0] ^ s->t[1];
}

static void threefish1024_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint64_t x00 = LOAD64L(CU8(pt)) + s->k[0];
	uint64_t x01 = LOAD64L(CU8(pt) + 8) + s->k[1];
	uint64_t x02 = LOAD64L(CU8(pt) + 16) + s->k[2];
	uint64_t x03 = LOAD64L(CU8(pt) + 24) + s->k[3];
	uint64_t x04 = LOAD64L(CU8(pt) + 32) + s->k[4];
	uint64_t x05 = LOAD64L(CU8(pt) + 40) + s->k[5];
	uint64_t x06 = LOAD64L(CU8(pt) + 48) + s->k[6];
	uint64_t x07 = LOAD64L(CU8(pt) + 56) + s->k[7];
	uint64_t x08 = LOAD64L(CU8(pt) + 64) + s->k[8];
	uint64_t x09 = LOAD64L(CU8(pt) + 72) + s->k[9];
	uint64_t x10 = LOAD64L(CU8(pt) + 80) + s->k[10];
	uint64_t x11 = LOAD64L(CU8(pt) + 88) + s->k[11];
	uint64_t x12 = LOAD64L(CU8(pt) + 96) + s->k[12];
	uint64_t x13 = LOAD64L(CU8(pt) + 104) + s->k[13] + s->t[0];
	uint64_t x14 = LOAD64L(CU8(pt) + 112) + s->k[14] + s->t[1];
	uint64_t x15 = LOAD64L(CU8(pt) + 120) + s->k[15];
	unsigned int r = 1;

	while(r <= s->rounds >> 2)
	{
		x00 += x01; x01 = ROL64_24(x01); x01 ^= x00;
		x02 += x03; x03 = ROL64_13(x03); x03 ^= x02;
		x04 += x05; x05 = ROL64_08(x05); x05 ^= x04;
		x06 += x07; x07 = ROL64_47(x07); x07 ^= x06;
		x08 += x09; x09 = ROL64_08(x09); x09 ^= x08;
		x10 += x11; x11 = ROL64_17(x11); x11 ^= x10;
		x12 += x13; x13 = ROL64_22(x13); x13 ^= x12;
		x14 += x15; x15 = ROL64_37(x15); x15 ^= x14;

		x00 += x09; x09 = ROL64_38(x09); x09 ^= x00;
		x02 += x13; x13 = ROL64_19(x13); x13 ^= x02;
		x06 += x11; x11 = ROL64_10(x11); x11 ^= x06;
		x04 += x15; x15 = ROL64_55(x15); x15 ^= x04;
		x10 += x07; x07 = ROL64_49(x07); x07 ^= x10;
		x12 += x03; x03 = ROL64_18(x03); x03 ^= x12;
		x14 += x05; x05 = ROL64_23(x05); x05 ^= x14;
		x08 += x01; x01 = ROL64_52(x01); x01 ^= x08;

		x00 += x07; x07 = ROL64_33(x07); x07 ^= x00;
		x02 += x05; x05 = ROL64_04(x05); x05 ^= x02;
		x04 += x03; x03 = ROL64_51(x03); x03 ^= x04;
		x06 += x01; x01 = ROL64_13(x01); x01 ^= x06;
		x12 += x15; x15 = ROL64_34(x15); x15 ^= x12;
		x14 += x13; x13 = ROL64_41(x13); x13 ^= x14;
		x08 += x11; x11 = ROL64_59(x11); x11 ^= x08;
		x10 += x09; x09 = ROL64_17(x09); x09 ^= x10;

		x00 += x15; x15 = ROL64_05(x15); x15 ^= x00;
		x02 += x11; x11 = ROL64_20(x11); x11 ^= x02;
		x06 += x13; x13 = ROL64_48(x13); x13 ^= x06;
		x04 += x09; x09 = ROL64_41(x09); x09 ^= x04;
		x14 += x01; x01 = ROL64_47(x01); x01 ^= x14;
		x08 += x05; x05 = ROL64_28(x05); x05 ^= x08;
		x10 += x03; x03 = ROL64_16(x03); x03 ^= x10;
		x12 += x07; x07 = ROL64_25(x07); x07 ^= x12;

		x00 += s->k[r % 17];
		x01 += s->k[(r + 1) % 17];
		x02 += s->k[(r + 2) % 17];
		x03 += s->k[(r + 3) % 17];
		x04 += s->k[(r + 4) % 17];
		x05 += s->k[(r + 5) % 17];
		x06 += s->k[(r + 6) % 17];
		x07 += s->k[(r + 7) % 17];
		x08 += s->k[(r + 8) % 17];
		x09 += s->k[(r + 9) % 17];
		x10 += s->k[(r + 10) % 17];
		x11 += s->k[(r + 11) % 17];
		x12 += s->k[(r + 12) % 17];
		x13 += s->k[(r + 13) % 17] + s->t[r % 3];
		x14 += s->k[(r + 14) % 17] + s->t[(r + 1) % 3];
		x15 += s->k[(r + 15) % 17] + r;
		r++;

		x00 += x01; x01 = ROL64_41(x01); x01 ^= x00;
		x02 += x03; x03 = ROL64_09(x03); x03 ^= x02;
		x04 += x05; x05 = ROL64_37(x05); x05 ^= x04;
		x06 += x07; x07 = ROL64_31(x07); x07 ^= x06;
		x08 += x09; x09 = ROL64_12(x09); x09 ^= x08;
		x10 += x11; x11 = ROL64_47(x11); x11 ^= x10;
		x12 += x13; x13 = ROL64_44(x13); x13 ^= x12;
		x14 += x15; x15 = ROL64_30(x15); x15 ^= x14;

		x00 += x09; x09 = ROL64_16(x09); x09 ^= x00;
		x02 += x13; x13 = ROL64_34(x13); x13 ^= x02;
		x06 += x11; x11 = ROL64_56(x11); x11 ^= x06;
		x04 += x15; x15 = ROL64_51(x15); x15 ^= x04;
		x10 += x07; x07 = ROL64_04(x07); x07 ^= x10;
		x12 += x03; x03 = ROL64_53(x03); x03 ^= x12;
		x14 += x05; x05 = ROL64_42(x05); x05 ^= x14;
		x08 += x01; x01 = ROL64_41(x01); x01 ^= x08;

		x00 += x07; x07 = ROL64_31(x07); x07 ^= x00;
		x02 += x05; x05 = ROL64_44(x05); x05 ^= x02;
		x04 += x03; x03 = ROL64_47(x03); x03 ^= x04;
		x06 += x01; x01 = ROL64_46(x01); x01 ^= x06;
		x12 += x15; x15 = ROL64_19(x15); x15 ^= x12;
		x14 += x13; x13 = ROL64_42(x13); x13 ^= x14;
		x08 += x11; x11 = ROL64_44(x11); x11 ^= x08;
		x10 += x09; x09 = ROL64_25(x09); x09 ^= x10;

		x00 += x15; x15 = ROL64_09(x15); x15 ^= x00;
		x02 += x11; x11 = ROL64_48(x11); x11 ^= x02;
		x06 += x13; x13 = ROL64_35(x13); x13 ^= x06;
		x04 += x09; x09 = ROL64_52(x09); x09 ^= x04;
		x14 += x01; x01 = ROL64_23(x01); x01 ^= x14;
		x08 += x05; x05 = ROL64_31(x05); x05 ^= x08;
		x10 += x03; x03 = ROL64_37(x03); x03 ^= x10;
		x12 += x07; x07 = ROL64_20(x07); x07 ^= x12;

		x00 += s->k[r % 17];
		x01 += s->k[(r + 1) % 17];
		x02 += s->k[(r + 2) % 17];
		x03 += s->k[(r + 3) % 17];
		x04 += s->k[(r + 4) % 17];
		x05 += s->k[(r + 5) % 17];
		x06 += s->k[(r + 6) % 17];
		x07 += s->k[(r + 7) % 17];
		x08 += s->k[(r + 8) % 17];
		x09 += s->k[(r + 9) % 17];
		x10 += s->k[(r + 10) % 17];
		x11 += s->k[(r + 11) % 17];
		x12 += s->k[(r + 12) % 17];
		x13 += s->k[(r + 13) % 17] + s->t[r % 3];
		x14 += s->k[(r + 14) % 17] + s->t[(r + 1) % 3];
		x15 += s->k[(r + 15) % 17] + r;
		r++;
	}

	STORE64L(x00, U8(ct));
	STORE64L(x01, U8(ct) + 8);
	STORE64L(x02, U8(ct) + 16);
	STORE64L(x03, U8(ct) + 24);
	STORE64L(x04, U8(ct) + 32);
	STORE64L(x05, U8(ct) + 40);
	STORE64L(x06, U8(ct) + 48);
	STORE64L(x07, U8(ct) + 56);
	STORE64L(x08, U8(ct) + 64);
	STORE64L(x09, U8(ct) + 72);
	STORE64L(x10, U8(ct) + 80);
	STORE64L(x11, U8(ct) + 88);
	STORE64L(x12, U8(ct) + 96);
	STORE64L(x13, U8(ct) + 104);
	STORE64L(x14, U8(ct) + 112);
	STORE64L(x15, U8(ct) + 120);
}

static void threefish1024_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint64_t x00 = LOAD64L(CU8(ct));
	uint64_t x01 = LOAD64L(CU8(ct) + 8);
	uint64_t x02 = LOAD64L(CU8(ct) + 16);
	uint64_t x03 = LOAD64L(CU8(ct) + 24);
	uint64_t x04 = LOAD64L(CU8(ct) + 32);
	uint64_t x05 = LOAD64L(CU8(ct) + 40);
	uint64_t x06 = LOAD64L(CU8(ct) + 48);
	uint64_t x07 = LOAD64L(CU8(ct) + 56);
	uint64_t x08 = LOAD64L(CU8(ct) + 64);
	uint64_t x09 = LOAD64L(CU8(ct) + 72);
	uint64_t x10 = LOAD64L(CU8(ct) + 80);
	uint64_t x11 = LOAD64L(CU8(ct) + 88);
	uint64_t x12 = LOAD64L(CU8(ct) + 96);
	uint64_t x13 = LOAD64L(CU8(ct) + 104);
	uint64_t x14 = LOAD64L(CU8(ct) + 112);
	uint64_t x15 = LOAD64L(CU8(ct) + 120);
	unsigned int r = s->rounds >> 2;

	while(r > 1)
	{
		x00 -= s->k[r % 17];
		x01 -= s->k[(r + 1) % 17];
		x02 -= s->k[(r + 2) % 17];
		x03 -= s->k[(r + 3) % 17];
		x04 -= s->k[(r + 4) % 17];
		x05 -= s->k[(r + 5) % 17];
		x06 -= s->k[(r + 6) % 17];
		x07 -= s->k[(r + 7) % 17];
		x08 -= s->k[(r + 8) % 17];
		x09 -= s->k[(r + 9) % 17];
		x10 -= s->k[(r + 10) % 17];
		x11 -= s->k[(r + 11) % 17];
		x12 -= s->k[(r + 12) % 17];
		x13 -= s->k[(r + 13) % 17] + s->t[r % 3];
		x14 -= s->k[(r + 14) % 17] + s->t[(r + 1) % 3];
		x15 -= s->k[(r + 15) % 17] + r;
		r--;

		x07 = ROR64_20(x07 ^ x12); x12 -= x07;
		x03 = ROR64_37(x03 ^ x10); x10 -= x03;
		x05 = ROR64_31(x05 ^ x08); x08 -= x05;
		x01 = ROR64_23(x01 ^ x14); x14 -= x01;
		x09 = ROR64_52(x09 ^ x04); x04 -= x09;
		x13 = ROR64_35(x13 ^ x06); x06 -= x13;
		x11 = ROR64_48(x11 ^ x02); x02 -= x11;
		x15 = ROR64_09(x15 ^ x00); x00 -= x15;

		x09 = ROR64_25(x09 ^ x10); x10 -= x09;
		x11 = ROR64_44(x11 ^ x08); x08 -= x11;
		x13 = ROR64_42(x13 ^ x14); x14 -= x13;
		x15 = ROR64_19(x15 ^ x12); x12 -= x15;
		x01 = ROR64_46(x01 ^ x06); x06 -= x01;
		x03 = ROR64_47(x03 ^ x04); x04 -= x03;
		x05 = ROR64_44(x05 ^ x02); x02 -= x05;
		x07 = ROR64_31(x07 ^ x00); x00 -= x07;

		x01 = ROR64_41(x01 ^ x08); x08 -= x01;
		x05 = ROR64_42(x05 ^ x14); x14 -= x05;
		x03 = ROR64_53(x03 ^ x12); x12 -= x03;
		x07 = ROR64_04(x07 ^ x10); x10 -= x07;
		x15 = ROR64_51(x15 ^ x04); x04 -= x15;
		x11 = ROR64_56(x11 ^ x06); x06 -= x11;
		x13 = ROR64_34(x13 ^ x02); x02 -= x13;
		x09 = ROR64_16(x09 ^ x00); x00 -= x09;

		x15 = ROR64_30(x15 ^ x14); x14 -= x15;
		x13 = ROR64_44(x13 ^ x12); x12 -= x13;
		x11 = ROR64_47(x11 ^ x10); x10 -= x11;
		x09 = ROR64_12(x09 ^ x08); x08 -= x09;
		x07 = ROR64_31(x07 ^ x06); x06 -= x07;
		x05 = ROR64_37(x05 ^ x04); x04 -= x05;
		x03 = ROR64_09(x03 ^ x02); x02 -= x03;
		x01 = ROR64_41(x01 ^ x00); x00 -= x01;

		x00 -= s->k[r % 17];
		x01 -= s->k[(r + 1) % 17];
		x02 -= s->k[(r + 2) % 17];
		x03 -= s->k[(r + 3) % 17];
		x04 -= s->k[(r + 4) % 17];
		x05 -= s->k[(r + 5) % 17];
		x06 -= s->k[(r + 6) % 17];
		x07 -= s->k[(r + 7) % 17];
		x08 -= s->k[(r + 8) % 17];
		x09 -= s->k[(r + 9) % 17];
		x10 -= s->k[(r + 10) % 17];
		x11 -= s->k[(r + 11) % 17];
		x12 -= s->k[(r + 12) % 17];
		x13 -= s->k[(r + 13) % 17] + s->t[r % 3];
		x14 -= s->k[(r + 14) % 17] + s->t[(r + 1) % 3];
		x15 -= s->k[(r + 15) % 17] + r;
		r--;

		x07 = ROR64_25(x07 ^ x12); x12 -= x07;
		x03 = ROR64_16(x03 ^ x10); x10 -= x03;
		x05 = ROR64_28(x05 ^ x08); x08 -= x05;
		x01 = ROR64_47(x01 ^ x14); x14 -= x01;
		x09 = ROR64_41(x09 ^ x04); x04 -= x09;
		x13 = ROR64_48(x13 ^ x06); x06 -= x13;
		x11 = ROR64_20(x11 ^ x02); x02 -= x11;
		x15 = ROR64_05(x15 ^ x00); x00 -= x15;

		x09 = ROR64_17(x09 ^ x10); x10 -= x09;
		x11 = ROR64_59(x11 ^ x08); x08 -= x11;
		x13 = ROR64_41(x13 ^ x14); x14 -= x13;
		x15 = ROR64_34(x15 ^ x12); x12 -= x15;
		x01 = ROR64_13(x01 ^ x06); x06 -= x01;
		x03 = ROR64_51(x03 ^ x04); x04 -= x03;
		x05 = ROR64_04(x05 ^ x02); x02 -= x05;
		x07 = ROR64_33(x07 ^ x00); x00 -= x07;

		x01 = ROR64_52(x01 ^ x08); x08 -= x01;
		x05 = ROR64_23(x05 ^ x14); x14 -= x05;
		x03 = ROR64_18(x03 ^ x12); x12 -= x03;
		x07 = ROR64_49(x07 ^ x10); x10 -= x07;
		x15 = ROR64_55(x15 ^ x04); x04 -= x15;
		x11 = ROR64_10(x11 ^ x06); x06 -= x11;
		x13 = ROR64_19(x13 ^ x02); x02 -= x13;
		x09 = ROR64_38(x09 ^ x00); x00 -= x09;

		x15 = ROR64_37(x15 ^ x14); x14 -= x15;
		x13 = ROR64_22(x13 ^ x12); x12 -= x13;
		x11 = ROR64_17(x11 ^ x10); x10 -= x11;
		x09 = ROR64_08(x09 ^ x08); x08 -= x09;
		x07 = ROR64_47(x07 ^ x06); x06 -= x07;
		x05 = ROR64_08(x05 ^ x04); x04 -= x05;
		x03 = ROR64_13(x03 ^ x02); x02 -= x03;
		x01 = ROR64_24(x01 ^ x00); x00 -= x01;
	}

	x00 -= s->k[0];
	x01 -= s->k[1];
	x02 -= s->k[2];
	x03 -= s->k[3];
	x04 -= s->k[4];
	x05 -= s->k[5];
	x06 -= s->k[6];
	x07 -= s->k[7];
	x08 -= s->k[8];
	x09 -= s->k[9];
	x10 -= s->k[10];
	x11 -= s->k[11];
	x12 -= s->k[12];
	x13 -= s->k[13] + s->t[0];
	x14 -= s->k[14] + s->t[1];
	x15 -= s->k[15];

	STORE64L(x00, U8(pt));
	STORE64L(x01, U8(pt) + 8);
	STORE64L(x02, U8(pt) + 16);
	STORE64L(x03, U8(pt) + 24);
	STORE64L(x04, U8(pt) + 32);
	STORE64L(x05, U8(pt) + 40);
	STORE64L(x06, U8(pt) + 48);
	STORE64L(x07, U8(pt) + 56);
	STORE64L(x08, U8(pt) + 64);
	STORE64L(x09, U8(pt) + 72);
	STORE64L(x10, U8(pt) + 80);
	STORE64L(x11, U8(pt) + 88);
	STORE64L(x12, U8(pt) + 96);
	STORE64L(x13, U8(pt) + 104);
	STORE64L(x14, U8(pt) + 112);
	STORE64L(x15, U8(pt) + 120);
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

	s->obj.desc = kripto_block_threefish1024;

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
	"Threefish1024",
	128, /* block size */
	128 /* max key */
};

const kripto_block_desc *const kripto_block_threefish1024 = &threefish1024;
