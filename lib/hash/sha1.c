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
#include <stddef.h>
#include <stdlib.h>
#include <limits.h>
#include <assert.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/rotate.h>
#include <kripto/memwipe.h>
#include <kripto/hash.h>
#include <kripto/desc/hash.h>
#include <kripto/object/hash.h>

#include <kripto/hash/sha1.h>

struct kripto_hash
{
	struct kripto_hash_object obj;
	uint64_t len;
	uint32_t h[5];
	uint8_t buf[64];
	unsigned int i;
	int o;
};

#define F0(X, Y, Z) (Z ^ (X & (Y ^ Z)))
#define F1(X, Y, Z) (X ^ Y ^ Z)
#define F2(X, Y, Z) ((X & Y) | (Z & (X | Y)))

#define G0(A, B, C, D, E, W)							\
{														\
	E += ROL32_05(A) + F0(B, C, D) + W + 0x5A827999;	\
	B = ROL32_30(B);									\
}

#define G1(A, B, C, D, E, W)							\
{														\
	E += ROL32_05(A) + F1(B, C, D) + W + 0x6ED9EBA1;	\
	B = ROL32_30(B);									\
}

#define G2(A, B, C, D, E, W)							\
{														\
	E += ROL32_05(A) + F2(B, C, D) + W + 0x8F1BBCDC;	\
	B = ROL32_30(B);									\
}

#define G3(A, B, C, D, E, W)							\
{														\
	E += ROL32_05(A) + F1(B, C, D) + W + 0xCA62C1D6;	\
	B = ROL32_30(B);									\
}

static kripto_hash *sha1_recreate
(
	kripto_hash *s,
	unsigned int r,
	size_t len
)
{
	(void)r;
	(void)len;
	s->len = s->o = s->i = 0;

	s->h[0] = 0x67452301;
	s->h[1] = 0xEFCDAB89;
	s->h[2] = 0x98BADCFE;
	s->h[3] = 0x10325476;
	s->h[4] = 0xC3D2E1F0;

	return s;
}

static void sha1_process(kripto_hash *s, const uint8_t *data)
{
	uint32_t a = s->h[0];
	uint32_t b = s->h[1];
	uint32_t c = s->h[2];
	uint32_t d = s->h[3];
	uint32_t e = s->h[4];
	uint32_t w[80];
	unsigned int i;

	w[0] = LOAD32B(data);
	w[1] = LOAD32B(data + 4);
	w[2] = LOAD32B(data + 8);
	w[3] = LOAD32B(data + 12);
	w[4] = LOAD32B(data + 16);
	w[5] = LOAD32B(data + 20);
	w[6] = LOAD32B(data + 24);
	w[7] = LOAD32B(data + 28);
	w[8] = LOAD32B(data + 32);
	w[9] = LOAD32B(data + 36);
	w[10] = LOAD32B(data + 40);
	w[11] = LOAD32B(data + 44);
	w[12] = LOAD32B(data + 48);
	w[13] = LOAD32B(data + 52);
	w[14] = LOAD32B(data + 56);
	w[15] = LOAD32B(data + 60);

	for(i = 16; i < 80; i++)
		w[i] = ROL32_01(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]);

	for(i = 0; i < 20;)
	{
		G0(a, b, c, d, e, w[i++]);
		G0(e, a, b, c, d, w[i++]);
		G0(d, e, a, b, c, w[i++]);
		G0(c, d, e, a, b, w[i++]);
		G0(b, c, d, e, a, w[i++]);
	}

	while(i < 40)
	{
		G1(a, b, c, d, e, w[i++]);
		G1(e, a, b, c, d, w[i++]);
		G1(d, e, a, b, c, w[i++]);
		G1(c, d, e, a, b, w[i++]);
		G1(b, c, d, e, a, w[i++]);
	}

	while(i < 60)
	{
		G2(a, b, c, d, e, w[i++]);
		G2(e, a, b, c, d, w[i++]);
		G2(d, e, a, b, c, w[i++]);
		G2(c, d, e, a, b, w[i++]);
		G2(b, c, d, e, a, w[i++]);
	}

	while(i < 80)
	{
		G3(a, b, c, d, e, w[i++]);
		G3(e, a, b, c, d, w[i++]);
		G3(d, e, a, b, c, w[i++]);
		G3(c, d, e, a, b, w[i++]);
		G3(b, c, d, e, a, w[i++]);
	}

	kripto_memwipe(w, 320);

	s->h[0] += a;
	s->h[1] += b;
	s->h[2] += c;
	s->h[3] += d;
	s->h[4] += e;
}

static void sha1_input
(
	kripto_hash *s,
	const void *in,
	size_t len
) 
{
	size_t i;

	s->len += len << 3;
	assert(s->len >= len << 3);

	for(i = 0; i < len; i++)
	{
		s->buf[s->i++] = CU8(in)[i];

		if(s->i == 64)
		{
			sha1_process(s, s->buf);
			s->i = 0;
		}
	}
}

static void sha1_finish(kripto_hash *s)
{
	s->buf[s->i++] = 0x80; /* pad */

	if(s->i > 56) /* not enough space for length */
	{
		while(s->i < 64) s->buf[s->i++] = 0;
		sha1_process(s, s->buf);
		s->i = 0;
	}
	while(s->i < 56) s->buf[s->i++] = 0;

	/* add length */
	//s->len << 3;
	STORE64B(s->len, s->buf + 56);

	sha1_process(s, s->buf);

	s->i = 0;
	s->o = -1;
}

static void sha1_output(kripto_hash *s, void *out, size_t len)
{
	unsigned int i;

	if(!s->o) sha1_finish(s);

	/* big endian */
	for(i = 0; i < len; s->i++, i++)
		U8(out)[i] = s->h[s->i >> 2] >> (24 - ((s->i & 3) << 3));
}

static kripto_hash *sha1_create(unsigned int r, size_t len)
{
	kripto_hash *s;

	s = malloc(sizeof(kripto_hash));
	if(!s) return 0;

	s->obj.desc = kripto_hash_sha1;

	(void)sha1_recreate(s, r, len);

	return s;
}

static void sha1_destroy(kripto_hash *s)
{
	kripto_memwipe(s, sizeof(kripto_hash));
	free(s);
}

static int sha1_hash
(
	unsigned int r,
	const void *in,
	size_t in_len,
	void *out,
	size_t out_len
)
{
	kripto_hash s;

	(void)sha1_recreate(&s, r, out_len);
	sha1_input(&s, in, in_len);
	sha1_output(&s, out, out_len);

	kripto_memwipe(&s, sizeof(kripto_hash));

	return 0;
}

static const kripto_hash_desc sha1 =
{
	&sha1_create,
	&sha1_recreate,
	&sha1_input,
	&sha1_output,
	&sha1_destroy,
	&sha1_hash,
	20, /* max output */
	64 /* block_size */
};

const kripto_hash_desc *const kripto_hash_sha1 = &sha1;
