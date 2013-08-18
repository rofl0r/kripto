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
#include <limits.h>
#include <assert.h>

#include <kripto/macros.h>
#include <kripto/memwipe.h>
#include <kripto/hash.h>
#include <kripto/hash_desc.h>

#include <kripto/hash/sha2_512.h>

struct kripto_hash
{
	kripto_hash_desc *hash;
	uint64_t h[8];
	uint64_t len[2];
	uint8_t buf[128];
	unsigned int r;
	unsigned int i;
	int o;
};

#define CH(X0, X1, X2) (X2 ^ (X0 & (X1 ^ X2)))
#define MAJ(X0, X1, X2) ((X0 & X1) | (X2 & (X0 | X1)))

#define S0(X) (ROR64(X, 1) ^ ROR64(X, 8) ^ ((X) >> 7))
#define S1(X) (ROR64(X, 19) ^ ROR64(X, 61) ^ ((X) >> 6))

#define E0(X) (ROR64(X, 28) ^ ROR64(X, 34) ^ ROR64(X, 39))
#define E1(X) (ROR64(X, 14) ^ ROR64(X, 18) ^ ROR64(X, 41))

static const uint64_t k[160] =
{
	0x428A2F98D728AE22, 0x7137449123EF65CD,
	0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
	0x3956C25BF348B538, 0x59F111F1B605D019,
	0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
	0xD807AA98A3030242, 0x12835B0145706FBE,
	0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
	0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1,
	0x9BDC06A725C71235, 0xC19BF174CF692694,
	0xE49B69C19EF14AD2, 0xEFBE4786384F25E3,
	0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
	0x2DE92C6F592B0275, 0x4A7484AA6EA6E483,
	0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
	0x983E5152EE66DFAB, 0xA831C66D2DB43210,
	0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
	0xC6E00BF33DA88FC2, 0xD5A79147930AA725,
	0x06CA6351E003826F, 0x142929670A0E6E70,
	0x27B70A8546D22FFC, 0x2E1B21385C26C926,
	0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
	0x650A73548BAF63DE, 0x766A0ABB3C77B2A8,
	0x81C2C92E47EDAEE6, 0x92722C851482353B,
	0xA2BFE8A14CF10364, 0xA81A664BBC423001,
	0xC24B8B70D0F89791, 0xC76C51A30654BE30,
	0xD192E819D6EF5218, 0xD69906245565A910,
	0xF40E35855771202A, 0x106AA07032BBD1B8,
	0x19A4C116B8D2D0C8, 0x1E376C085141AB53,
	0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
	0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB,
	0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
	0x748F82EE5DEFB2FC, 0x78A5636F43172F60,
	0x84C87814A1F0AB72, 0x8CC702081A6439EC,
	0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9,
	0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
	0xCA273ECEEA26619C, 0xD186B8C721C0C207,
	0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
	0x06F067AA72176FBA, 0x0A637DC5A2C898A6,
	0x113F9804BEF90DAE, 0x1B710B35131C471B,
	0x28DB77F523047D84, 0x32CAAB7B40C72493,
	0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
	0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A,
	0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
	0x7BA0EA2D98160007, 0x7EABF2D0C21F964A,
	0x8DBE8D038B409545, 0x90BB1721582E8285,
	0x99A2AD45936D4E61, 0x9F86E289FE03E739,
	0xA84C4472FAA9A82F, 0xB3DF34FCE89E0532,
	0xB99BB8D7B173534F, 0xBC76CBAB1AEA1F9C,
	0xC226A69A780F3CC3, 0xD304F19AA233957D,
	0xDE1BE20A212129DD, 0xE39BB43755141950,
	0xEE84927CEA48DDD2, 0xF3EDD2773C523B67,
	0xFBFDFE53A8D32F2A, 0x0BEE2C7AB77E9E25,
	0x0E90181CF1B09E56, 0x25F57204C725BED8,
	0x2DA45582CD598B32, 0x3A52C34C203BFCF3,
	0x41DC0172CD1991C1, 0x495796FCB33CC1C0,
	0x4BD31FC693F9F16E, 0x533CDE2115F5A9A0,
	0x5F7ABFE36E99C1D3, 0x66C206B310A57E6F,
	0x6DFCC6BC39603F61, 0x7062F20F86FD1052,
	0x778D51277ADEC865, 0x7EABA3CC25DA7048,
	0x8363ECCC37A5BE05, 0x85BE1C253BEBA54E,
	0x93C04028F348BBC5, 0x9F4A205FD05B2148,
	0xA19535651CA6D2DE, 0xA627BB0FBF027BC7,
	0xACFA80891DA2F06B, 0xB3C29B23031A7F9D,
	0xB602F6FAC7D3D74D, 0xC36CEE0A10C7BA49,
	0xC7DC81EEA9EBAD4F, 0xCE7B8471B0F809DF,
	0xD740288C84DF269C, 0xE21DBA7AC2290607,
	0xEABBFF66BE175964, 0xF56A9E60F62CEA92,
	0xFDE41D729D126EAB, 0x0434D0970E42E781,
	0x0A7CB752A3F1CD86, 0x0EA7D22D6BCD7382,
	0x16F2987F9495A5EE, 0x1D20CDCD45B8DE1E,
	0x213AF85A39B0C320, 0x2964505C52A2F35B,
	0x2D738E114181E082, 0x3B8CEA0E71C58AAF,
	0x4584E6AE9F54016E, 0x515F4356903DCCC2,
	0x5356112DDFD5A8E9, 0x5D1BC3EDBE2C897A,
	0x5F0DA9F8ED53548B, 0x62EF0BE4D5492E78,
	0x64DE896EACE0BE7F, 0x6E801BA3078AE05F,
	0x7BDB3595CDADF50A, 0x7FA5377856834C98,
	0x818916BAD3D008A8, 0x854E959F834021A7,
	0x926A82C27137E2C6, 0x9622C7BA7D179197,
	0x97FDD5929D59CE21, 0x9BB1CB7470162D7E,
	0xAE0B55609FFEA9D5, 0xB1AE88AB4ECA7239,
	0xB8ECC9F6468460A1, 0xC1EB8968A81A3124,
	0xC911DD821BB6B418, 0xCCA11FE32D0C58D0
};

static kripto_hash *sha2_512_recreate
(
	kripto_hash *s,
	size_t len,
	unsigned int r
)
{
	s->len[1] = s->len[0] = s->o = s->i = 0;

	s->r = r;
	if(!s->r) s->r = 80;

	if(len > 48)
	{
		/* 512 */
		s->h[0] = 0x6A09E667F3BCC908;
		s->h[1] = 0xBB67AE8584CAA73B;
		s->h[2] = 0x3C6EF372FE94F82B;
		s->h[3] = 0xA54FF53A5F1D36F1;
		s->h[4] = 0x510E527FADE682D1;
		s->h[5] = 0x9B05688C2B3E6C1F;
		s->h[6] = 0x1F83D9ABFB41BD6B;
		s->h[7] = 0x5BE0CD19137E2179;
	}
	else
	{
		/* 384 */
		s->h[0] = 0xCBBB9D5DC1059ED8;
		s->h[1] = 0x629A292A367CD507;
		s->h[2] = 0x9159015A3070DD17;
		s->h[3] = 0x152FECD8F70E5939;
		s->h[4] = 0x67332667FFC00B31;
		s->h[5] = 0x8EB44A8768581511;
		s->h[6] = 0xDB0C2E0D64F98FA7;
		s->h[7] = 0x47B5481DBEFA4FA4;
	}

	return s;
}

static void sha2_512_process(kripto_hash *s, const uint8_t *in)
{
	uint64_t a = s->h[0];
	uint64_t b = s->h[1];
	uint64_t c = s->h[2];
	uint64_t d = s->h[3];
	uint64_t e = s->h[4];
	uint64_t f = s->h[5];
	uint64_t g = s->h[6];
	uint64_t h = s->h[7];
	uint64_t t;
	uint64_t w[160];
	unsigned int i;

	w[0] = U8TO64_BE(in);
	w[1] = U8TO64_BE(in + 8);
	w[2] = U8TO64_BE(in + 16);
	w[3] = U8TO64_BE(in + 24);
	w[4] = U8TO64_BE(in + 32);
	w[5] = U8TO64_BE(in + 40);
	w[6] = U8TO64_BE(in + 48);
	w[7] = U8TO64_BE(in + 56);
	w[8] = U8TO64_BE(in + 64);
	w[9] = U8TO64_BE(in + 72);
	w[10] = U8TO64_BE(in + 80);
	w[11] = U8TO64_BE(in + 88);
	w[12] = U8TO64_BE(in + 96);
	w[13] = U8TO64_BE(in + 104);
	w[14] = U8TO64_BE(in + 112);
	w[15] = U8TO64_BE(in + 120);

	for(i = 16; i < s->r; i++)
		w[i] = w[i - 16] + S0(w[i - 15]) +  w[i - 7] + S1(w[i - 2]);

	for(i = 0; i < s->r; i++)
	{
		h += E1(e) + CH(e, f, g) + k[i] + w[i];
		d += h;
		h += E0(a) + MAJ(a, b, c);

		t = h;
		h = g;
		g = f;
		f = e;
		e = d;
		d = c;
		c = b;
		b = a;
		a = t;
	}

	kripto_memwipe(w, s->r << 2);

	s->h[0] += a;
	s->h[1] += b;
	s->h[2] += c;
	s->h[3] += d;
	s->h[4] += e;
	s->h[5] += f;
	s->h[6] += g;
	s->h[7] += h;
}

static void sha2_512_input
(
	kripto_hash *s,
	const void *in,
	size_t len
) 
{
	size_t i;

	s->len[0] += len << 3;
	/* TODO: s->len[1] */
	assert(s->len[0] >= len << 3);

	for(i = 0; i < len; i++)
	{
		s->buf[s->i++] = CU8(in)[i];

		if(s->i == 128)
		{
			sha2_512_process(s, s->buf);
			s->i = 0;
		}
	}
}

static void sha2_512_finish(kripto_hash *s)
{
	s->buf[s->i++] = 0x80; /* pad */

	if(s->i > 112) /* not enough space for length */
	{
		while(s->i < 128) s->buf[s->i++] = 0;
		sha2_512_process(s, s->buf);
		s->i = 0;
	}
	while(s->i < 112) s->buf[s->i++] = 0;

	/* add length */
	U64TO8_BE(s->len[1], s->buf + 112);
	U64TO8_BE(s->len[0], s->buf + 120);

	sha2_512_process(s, s->buf);

	s->i = 0;
	s->o = -1;
}

static void sha2_512_output(kripto_hash *s, void *out, size_t len)
{
	unsigned int i;

	if(!s->o) sha2_512_finish(s);

	/* big endian */
	for(i = 0; i < len; s->i++, i++)
		U8(out)[i] = s->h[s->i >> 3] >> (56 - ((s->i & 7) << 3));
}

static kripto_hash *sha2_512_create(size_t len, unsigned int r)
{
	kripto_hash *s;

	s = malloc(sizeof(kripto_hash));
	if(!s) return 0;

	s->hash = kripto_hash_sha2_512;

	(void)sha2_512_recreate(s, len, r);

	return s;
}

static void sha2_512_destroy(kripto_hash *s)
{
	kripto_memwipe(s, sizeof(kripto_hash));
	free(s);
}

static int sha2_512_hash
(
	unsigned int r,
	const void *in,
	size_t in_len,
	void *out,
	size_t out_len
)
{
	kripto_hash s;

	(void)sha2_512_recreate(&s, out_len, r);
	sha2_512_input(&s, in, in_len);
	sha2_512_output(&s, out, out_len);

	kripto_memwipe(&s, sizeof(kripto_hash));

	return 0;
}

static const struct kripto_hash_desc sha2_512 =
{
	&sha2_512_create,
	&sha2_512_recreate,
	&sha2_512_input,
	&sha2_512_output,
	&sha2_512_destroy,
	&sha2_512_hash,
	64, /* max output */
	128 /* block_size */
};

kripto_hash_desc *const kripto_hash_sha2_512 = &sha2_512;
