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

#include <assert.h>

#include <kripto/stream_desc.h>

#include <kripto/stream.h>

struct kripto_stream
{
	kripto_stream_desc *desc;
};

kripto_stream *kripto_stream_create
(
	kripto_stream_desc *desc,
	const void *key,
	const unsigned int key_len,
	const void *iv,
	const unsigned int iv_len,
	const unsigned int r
)
{
	assert(desc);
	assert(desc->create);

	return desc->create(key, key_len, iv, iv_len, r);
}

size_t kripto_stream_encrypt
(
	kripto_stream *s,
	const void *pt,
	void *ct,
	const size_t len
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->encrypt);

	return s->desc->encrypt(s, pt, ct, len);
}

size_t kripto_stream_decrypt
(
	kripto_stream *s,
	const void *ct,
	void *pt,
	const size_t len
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->decrypt);

	return s->desc->decrypt(s, ct, pt, len);
}

size_t kripto_stream_prng
(
	kripto_stream *s,
	void *out,
	const size_t len
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->prng);

	return s->desc->prng(s, out, len);
}

void kripto_stream_destroy(kripto_stream *s)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->destroy);

	s->desc->destroy(s);
}

unsigned int kripto_stream_max_key(kripto_stream_desc *desc)
{
	assert(desc);
	assert(s->max_key);

	return desc->max_key;
}

unsigned int kripto_stream_max_iv(kripto_stream_desc *desc)
{
	assert(desc);
	assert(s->max_iv);

	return desc->max_iv;
}

unsigned int kripto_stream_max_rounds(kripto_stream_desc *desc)
{
	assert(desc);
	assert(s->max_rounds);

	return desc->max_rounds;
}

unsigned int kripto_stream_default_rounds(kripto_stream_desc *desc)
{
	assert(desc);
	assert(s->default_rounds);

	return desc->default_rounds;
}
