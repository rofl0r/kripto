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

#include <kripto/hash_desc.h>

#include <kripto/hash.h>

struct kripto_hash
{
	const kripto_hash_desc *desc;
};

kripto_hash *kripto_hash_create
(
	const kripto_hash_desc *desc,
	unsigned int rounds,
	size_t len
)
{
	assert(desc);
	assert(desc->create);
	assert(len <= kripto_hash_maxout(desc));

	return desc->create(rounds, len);
}

kripto_hash *kripto_hash_recreate
(
	kripto_hash *s,
	unsigned int rounds,
	size_t len
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->recreate);
	assert(len <= kripto_hash_maxout(s->desc));

	return s->desc->recreate(s, rounds, len);
}

void kripto_hash_input(kripto_hash *s, const void *in, size_t len)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->input);

	s->desc->input(s, in, len);
}

void kripto_hash_output(kripto_hash *s, void *out, size_t len)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->output);
	assert(len <= kripto_hash_maxout(s->desc));

	s->desc->output(s, out, len);
}

void kripto_hash_destroy(kripto_hash *s)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->destroy);

	s->desc->destroy(s);
}

int kripto_hash_all
(
	const kripto_hash_desc *desc,
	unsigned int rounds,
	const void *in,
	size_t in_len,
	void *out,
	size_t out_len
)
{
	assert(desc);
	assert(desc->hash_all);
	assert(out_len <= kripto_hash_maxout(desc));

	return desc->hash_all(rounds, in, in_len, out, out_len);
}

const kripto_hash_desc *kripto_hash_getdesc(const kripto_hash *s)
{
	assert(s);
	assert(s->desc);

	return s->desc;
}

size_t kripto_hash_maxout(const kripto_hash_desc *desc)
{
	assert(desc);
	assert(desc->maxout);

	return desc->maxout;
}

unsigned int kripto_hash_blocksize(const kripto_hash_desc *desc)
{
	assert(desc);
	assert(desc->blocksize);

	return desc->blocksize;
}
