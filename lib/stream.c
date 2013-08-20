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
#include <stdint.h>

#include <kripto/stream_desc.h>

#include <kripto/stream.h>

struct kripto_stream
{
	const kripto_stream_desc *desc;
};

kripto_stream *kripto_stream_create
(
	const kripto_stream_desc *desc,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len
)
{
	assert(desc);
	assert(desc->create);

	assert(key);
	assert(key_len);
	assert(key_len <= kripto_stream_maxkey(desc));
	assert(iv_len <= kripto_stream_maxiv(desc));
	if(iv_len) assert(iv);

	return desc->create(desc, rounds, key, key_len, iv, iv_len);
}

kripto_stream *kripto_stream_recreate
(
	kripto_stream *s,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->recreate);

	assert(key);
	assert(key_len);
	assert(key_len <= kripto_stream_maxkey(s->desc));
	assert(iv_len <= kripto_stream_maxiv(s->desc));
	if(iv_len) assert(iv);

	return s->desc->recreate(s, rounds, key, key_len, iv, iv_len);
}

size_t kripto_stream_encrypt
(
	kripto_stream *s,
	const void *pt,
	void *ct,
	size_t len
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
	size_t len
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
	size_t len
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

const kripto_stream_desc *kripto_stream_getdesc(const kripto_stream *s)
{
	assert(s);
	assert(s->desc);

	return s->desc;
}

unsigned int kripto_stream_maxkey(const kripto_stream_desc *desc)
{
	assert(desc);
	assert(desc->maxkey);

	return desc->maxkey;
}

unsigned int kripto_stream_maxiv(const kripto_stream_desc *desc)
{
	assert(desc);

	return desc->maxiv;
}
