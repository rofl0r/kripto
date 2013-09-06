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
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <kripto/macros.h>
#include <kripto/memwipe.h>
#include <kripto/hash.h>
#include <kripto/desc/hash.h>

#include <kripto/hash/keccak800.h>

struct kripto_hash
{
	const kripto_hash_desc *hash;
	unsigned int r;
	unsigned int rate;
	unsigned int i;
	int o;
	uint8_t s[100];
};

static const uint32_t rc[40] = 
{
	0x00000001, 0x00008082, 0x8000808A, 0x00008000,
	0x0000808B, 0x80000001, 0x00008081, 0x80008009,
	0x0000008A, 0x00000088, 0x80008009, 0x8000000A,
	0x8000808B, 0x8000008B, 0x80008089, 0x80008003,
	0x80008002, 0x80000080, 0x0000800A, 0x0000000A,
	0x00008081, 0x80008080, 0x80000001, 0x00008008,
	0x00008082, 0x0000800A, 0x80000003, 0x00000009,
	0x80008082, 0x00008009, 0x80000080, 0x00008083,
	0x80000081, 0x00000001, 0x0000800B, 0x00008001,
	0x00000080, 0x80008000, 0x00008001, 0x00000009
};

static void keccak800_F(kripto_hash *s)
{
	uint32_t a0 = U8TO32_LE(s->s);
	uint32_t a1 = U8TO32_LE(s->s + 8);
	uint32_t a2 = U8TO32_LE(s->s + 16);
	uint32_t a3 = U8TO32_LE(s->s + 24);
	uint32_t a4 = U8TO32_LE(s->s + 32);
	uint32_t a5 = U8TO32_LE(s->s + 40);
	uint32_t a6 = U8TO32_LE(s->s + 48);
	uint32_t a7 = U8TO32_LE(s->s + 56);
	uint32_t a8 = U8TO32_LE(s->s + 64);
	uint32_t a9 = U8TO32_LE(s->s + 72);
	uint32_t a10 = U8TO32_LE(s->s + 80);
	uint32_t a11 = U8TO32_LE(s->s + 88);
	uint32_t a12 = U8TO32_LE(s->s + 96);
	uint32_t a13 = U8TO32_LE(s->s + 104);
	uint32_t a14 = U8TO32_LE(s->s + 112);
	uint32_t a15 = U8TO32_LE(s->s + 120);
	uint32_t a16 = U8TO32_LE(s->s + 128);
	uint32_t a17 = U8TO32_LE(s->s + 136);
	uint32_t a18 = U8TO32_LE(s->s + 144);
	uint32_t a19 = U8TO32_LE(s->s + 152);
	uint32_t a20 = U8TO32_LE(s->s + 160);
	uint32_t a21 = U8TO32_LE(s->s + 168);
	uint32_t a22 = U8TO32_LE(s->s + 176);
	uint32_t a23 = U8TO32_LE(s->s + 184);
	uint32_t a24 = U8TO32_LE(s->s + 192);

	uint32_t b0;
	uint32_t b1;
	uint32_t b2;
	uint32_t b3;
	uint32_t b4;
	uint32_t b5;
	uint32_t b6;
	uint32_t b7;
	uint32_t b8;
	uint32_t b9;
	uint32_t b10;
	uint32_t b11;
	uint32_t b12;
	uint32_t b13;
	uint32_t b14;
	uint32_t b15;
	uint32_t b16;
	uint32_t b17;
	uint32_t b18;
	uint32_t b19;
	uint32_t b20;
	uint32_t b21;
	uint32_t b22;
	uint32_t b23;
	uint32_t b24;

	uint32_t c0;
	uint32_t c1;
	uint32_t c2;
	uint32_t c3;
	uint32_t c4;

	uint32_t d0;
	uint32_t d1;
	uint32_t d2;
	uint32_t d3;
	uint32_t d4;

	unsigned int i;

	for(i = 0; i < s->r; i++)
	{
		c0 = a0 ^ a5 ^ a10 ^ a15 ^ a20;
		c1 = a1 ^ a6 ^ a11 ^ a16 ^ a21;
		c2 = a2 ^ a7 ^ a12 ^ a17 ^ a22;
		c3 = a3 ^ a8 ^ a13 ^ a18 ^ a23;
		c4 = a4 ^ a9 ^ a14 ^ a19 ^ a24;

		d0 = ROL32(c1, 1) ^ c4;
		d1 = ROL32(c2, 1) ^ c0;
		d2 = ROL32(c3, 1) ^ c1;
		d3 = ROL32(c4, 1) ^ c2;
		d4 = ROL32(c0, 1) ^ c3;

		a0 ^= d0;
		c0 = a0;
		a6 ^= d1;
		c1 = ROL32(a6, 12);
		a12 ^= d2;
		c2 = ROL32(a12, 11);
		a18 ^= d3;
		c3 = ROL32(a18, 21);
		a24 ^= d4;
		c4 = ROL32(a24, 14);

		b0 = c0 ^ ((~c1) & c2) ^ rc[i];
		b1 = c1 ^ ((~c2) & c3);
		b2 = c2 ^ ((~c3) & c4);
		b3 = c3 ^ ((~c4) & c0);
		b4 = c4 ^ ((~c0) & c1);

		a3 ^= d3;
		c0 = ROL32(a3, 28);
		a9 ^= d4;
		c1 = ROL32(a9, 20);
		a10 ^= d0;
		c2 = ROL32(a10, 3);
		a16 ^= d1;
		c3 = ROL32(a16, 13);
		a22 ^= d2;
		c4 = ROL32(a22, 29);

		b5 = c0 ^ ((~c1) & c2);
		b6 = c1 ^ ((~c2) & c3);
		b7 = c2 ^ ((~c3) & c4);
		b8 = c3 ^ ((~c4) & c0);
		b9 = c4 ^ ((~c0) & c1);

		a1 ^= d1;
		c0 = ROL32(a1, 1);
		a7 ^= d2;
		c1 = ROL32(a7, 6);
		a13 ^= d3;
		c2 = ROL32(a13, 25);
		a19 ^= d4;
		c3 = ROL32(a19, 8);
		a20 ^= d0;
		c4 = ROL32(a20, 18);

		b10 = c0 ^ ((~c1) & c2);
		b11 = c1 ^ ((~c2) & c3);
		b12 = c2 ^ ((~c3) & c4);
		b13 = c3 ^ ((~c4) & c0);
		b14 = c4 ^ ((~c0) & c1);

		a4 ^= d4;
		c0 = ROL32(a4, 27);
		a5 ^= d0;
		c1 = ROL32(a5, 4);
		a11 ^= d1;
		c2 = ROL32(a11, 10);
		a17 ^= d2;
		c3 = ROL32(a17, 15);
		a23 ^= d3;
		c4 = ROL32(a23, 24);

		b15 = c0 ^ ((~c1) & c2);
		b16 = c1 ^ ((~c2) & c3);
		b17 = c2 ^ ((~c3) & c4);
		b18 = c3 ^ ((~c4) & c0);
		b19 = c4 ^ ((~c0) & c1);

		a2 ^= d2;
		c0 = ROL32(a2, 30);
		a8 ^= d3;
		c1 = ROL32(a8, 23);
		a14 ^= d4;
		c2 = ROL32(a14, 7);
		a15 ^= d0;
		c3 = ROL32(a15, 9);
		a21 ^= d1;
		c4 = ROL32(a21, 2);

		b20 = c0 ^ ((~c1) & c2);
		b21 = c1 ^ ((~c2) & c3);
		b22 = c2 ^ ((~c3) & c4);
		b23 = c3 ^ ((~c4) & c0);
		b24 = c4 ^ ((~c0) & c1);

		a0 = b0;
		a1 = b1;
		a2 = b2;
		a3 = b3;
		a4 = b4;
		a5 = b5;
		a6 = b6;
		a7 = b7;
		a8 = b8;
		a9 = b9;
		a10 = b10;
		a11 = b11;
		a12 = b12;
		a13 = b13;
		a14 = b14;
		a15 = b15;
		a16 = b16;
		a17 = b17;
		a18 = b18;
		a19 = b19;
		a20 = b20;
		a21 = b21;
		a22 = b22;
		a23 = b23;
		a24 = b24;
	}

	U32TO8_LE(a0, s->s);
	U32TO8_LE(a1, s->s + 8);
	U32TO8_LE(a2, s->s + 16);
	U32TO8_LE(a3, s->s + 24);
	U32TO8_LE(a4, s->s + 32);
	U32TO8_LE(a5, s->s + 40);
	U32TO8_LE(a6, s->s + 48);
	U32TO8_LE(a7, s->s + 56);
	U32TO8_LE(a8, s->s + 64);
	U32TO8_LE(a9, s->s + 72);
	U32TO8_LE(a10, s->s + 80);
	U32TO8_LE(a11, s->s + 88);
	U32TO8_LE(a12, s->s + 96);
	U32TO8_LE(a13, s->s + 104);
	U32TO8_LE(a14, s->s + 112);
	U32TO8_LE(a15, s->s + 120);
	U32TO8_LE(a16, s->s + 128);
	U32TO8_LE(a17, s->s + 136);
	U32TO8_LE(a18, s->s + 144);
	U32TO8_LE(a19, s->s + 152);
	U32TO8_LE(a20, s->s + 160);
	U32TO8_LE(a21, s->s + 168);
	U32TO8_LE(a22, s->s + 176);
	U32TO8_LE(a23, s->s + 184);
	U32TO8_LE(a24, s->s + 192);
}

static kripto_hash *keccak800_recreate
(
	kripto_hash *s,
	unsigned int r,
	size_t len
)
{
	s->o = s->i = 0;

	s->r = r;
	if(!s->r) s->r = 20;

	s->rate = 100 - (len << 1);

	memset(s->s, 0, 200);

	return s;
}

static void keccak800_input
(
	kripto_hash *s,
	const void *in,
	size_t len
) 
{
	size_t i;

	/* switch back to input mode */
	if(s->o) s->o = s->i = 0;

	/* input */
	for(i = 0; i < len; i++)
	{
		s->s[s->i++] ^= CU8(in)[i];

		if(s->i == s->rate)
		{
			keccak800_F(s);
			s->i = 0;
		}
	}
}

static void keccak800_output(kripto_hash *s, void *out, size_t len)
{
	size_t i;

	/* switch to output mode */
	if(!s->o)
	{
		/* pad */
		s->s[s->i] ^= 0x01;
		s->s[s->rate - 1] ^= 0x80;

		keccak800_F(s);

		s->i = 0;
		s->o = -1;
	}

	/* output */
	for(i = 0; i < len; i++)
	{
		if(s->i == s->rate)
		{
			keccak800_F(s);
			s->i = 0;
		}

		U8(out)[i] = s->s[s->i++];
	}
}

static kripto_hash *keccak800_create(unsigned int r, size_t len)
{
	kripto_hash *s;

	s = malloc(sizeof(struct kripto_hash));
	if(!s) return 0;

	s->hash = kripto_hash_keccak800;

	(void)keccak800_recreate(s, r, len);

	return s;
}

static void keccak800_destroy(kripto_hash *s) 
{
	kripto_memwipe(s, sizeof(kripto_hash));
	free(s);
}

static int keccak800_hash
(
	unsigned int r,
	const void *in,
	size_t in_len,
	void *out,
	size_t out_len
)
{
	kripto_hash s;

	(void)keccak800_recreate(&s, r, out_len);
	keccak800_input(&s, in, in_len);
	keccak800_output(&s, out, out_len);

	kripto_memwipe(&s, sizeof(kripto_hash));

	return 0;
}

static const kripto_hash_desc keccak800 =
{
	&keccak800_create,
	&keccak800_recreate,
	&keccak800_input,
	&keccak800_output,
	&keccak800_destroy,
	&keccak800_hash,
	SIZE_MAX, /* max output */
	100 /* block_size */
};

const kripto_hash_desc *const kripto_hash_keccak800 = &keccak800;
