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

/* modifed by Wei Dai from Joan Daemen's 3way.c
The original code and all modifications are in the public domain. */

#include <stdint.h>
#include <stdlib.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/rotate.h>
#include <kripto/memwipe.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>
#include <kripto/object/block.h>

#include <kripto/block/3way.h>

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int r;
	uint32_t k[3];
	uint32_t dk[3];
};

static const uint16_t rc_e[12] =
{
	0x0B0B, 0x1616, 0x2C2C, 0x5858,
	0xB0B0, 0x7171, 0xE2E2, 0xD5D5,
	0xBBBB, 0x6767, 0xCECE, 0x8D8D
};

static const uint16_t rc_d[12] =
{
	0xB1B1, 0x7373, 0xE6E6, 0xDDDD,
	0xABAB, 0x4747, 0x8E8E, 0x0D0D,
	0x1A1A, 0x3434, 0x6868, 0xD0D0
};

static inline uint32_t rev_bytes(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) && (defined(__i386__) || defined(__x86_64__))
	__asm__ ("bswap %0" : "=r" (x) : "0" (x));
	return x;
#else
	return (ROR32_08(x) & 0xFF00FF00) | (ROL32_08(x) & 0x00FF00FF);
#endif
}

static inline uint32_t rev_bits(uint32_t x)
{
	x = ((x & 0xAAAAAAAA) >> 1) | ((x & 0x55555555) << 1);
	x = ((x & 0xCCCCCCCC) >> 2) | ((x & 0x33333333) << 2);

	return ((x & 0xF0F0F0F0) >> 4) | ((x & 0x0F0F0F0F) << 4);
}

static inline void MU(uint32_t *x)
{
	uint32_t t;

	x[1] = rev_bits(x[1]);
	t = rev_bits(x[0]);
	x[0] = rev_bits(x[2]);
	x[2] = t;
}

static inline void PI_GAMMA_PI(uint32_t *x)
{
	uint32_t t0;
	uint32_t t2;

	t2 = ROL32_01(x[2]);
	t0 = ROL32_22(x[0]);
	x[0] = ROL32_01(t0 ^ (x[1] | (~t2)));
	x[2] = ROL32_22(t2 ^ (t0 | (~x[1])));
	x[1] ^= t2 | (~t0);
}

/* thanks to Paulo Barreto for this optimized THETA() */
static inline void THETA(uint32_t *x)
{
	uint32_t t0;
	uint32_t t1;
	uint32_t c;

	c = x[0] ^ x[1] ^ x[2];
	c = ROL32_16(c) ^ ROL32_08(c);
	t0 = (x[0] << 24) ^ (x[2] >> 8) ^ (x[1] << 8) ^ (x[0] >> 24);
	t1 = (x[1] << 24) ^ (x[0] >> 8) ^ (x[2] << 8) ^ (x[1] >> 24);
	x[0] ^= c ^ t0;
	x[1] ^= c ^ t1;
	x[2] ^= c ^ (t0 >> 16) ^ (t1 << 16);
}

static void threeway_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint32_t x[3];
	unsigned int i;

	x[0] = LOAD32B(CU8(pt));
	x[1] = LOAD32B(CU8(pt) + 4);
	x[2] = LOAD32B(CU8(pt) + 8);

	for(i = 0; i < s->r; i++)
	{
		x[0] ^= s->k[0] ^ (rc_e[i] << 16);
		x[1] ^= s->k[1];
		x[2] ^= s->k[2] ^ rc_e[i];
		THETA(x);
		PI_GAMMA_PI(x);
	}
	x[0] ^= s->k[0] ^ (rc_e[i] << 16);
	x[1] ^= s->k[1];
	x[2] ^= s->k[2] ^ rc_e[i];
	THETA(x);

	STORE32B(x[0], U8(ct));
	STORE32B(x[1], U8(ct) + 4);
	STORE32B(x[2], U8(ct) + 8);
}

static void threeway_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint32_t x[3];
	unsigned int i;

	x[0] = LOAD32L(CU8(ct));
	x[1] = LOAD32L(CU8(ct) + 4);
	x[2] = LOAD32L(CU8(ct) + 8);

	MU(x);
	for(i = 0; i < s->r; i++)
	{
		x[0] ^= s->dk[0] ^ (rc_d[i] << 16);
		x[1] ^= s->dk[1];
		x[2] ^= s->dk[2] ^ rc_d[i];
		THETA(x);
		PI_GAMMA_PI(x);
	}
	x[0] ^= s->dk[0] ^ (rc_d[i] << 16);
	x[1] ^= s->dk[1];
	x[2] ^= s->dk[2] ^ rc_d[i];
	THETA(x);
	MU(x);

	STORE32L(x[0], U8(pt));
	STORE32L(x[1], U8(pt) + 4);
	STORE32L(x[2], U8(pt) + 8);
}

static kripto_block *threeway_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	unsigned int i;

	if(!r) s->r = 11;
	else s->r = r;

	s->k[0] = s->k[1] = s->k[2] = 0;

	for(i = 0; i < key_len; i++)
		s->k[i >> 2] |= CU8(key)[i] << (24 - ((i & 3) << 3));

	/* decryption key */
	s->dk[0] = s->k[0];
	s->dk[1] = s->k[1];
	s->dk[2] = s->k[2];
	THETA(s->dk);
	MU(s->dk);
	s->dk[0] = rev_bytes(s->dk[0]);
	s->dk[1] = rev_bytes(s->dk[1]);
	s->dk[2] = rev_bytes(s->dk[2]);

	return s;
}

static kripto_block *threeway_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	s = malloc(sizeof(kripto_block));
	if(!s) return 0;

	s->obj.desc = kripto_block_3way;

	return threeway_recreate(s, r, key, key_len);
}

static void threeway_destroy(kripto_block *s)
{
	kripto_memwipe(s, sizeof(kripto_block));
	free(s);
}

static const kripto_block_desc threeway =
{
	&threeway_create,
	&threeway_recreate,
	0,
	&threeway_encrypt,
	&threeway_decrypt,
	&threeway_destroy,
	12, /* block size */
	12 /* max key */
};

const kripto_block_desc *const kripto_block_3way = &threeway;
