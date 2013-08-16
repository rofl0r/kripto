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

#include <kripto/authstream_desc.h>

#include <kripto/authstream.h>

struct kripto_authstream
{
	kripto_authstream_desc *desc;
};

kripto_authstream *kripto_authstream_create
(
	kripto_authstream_desc *desc,
	const void *key,
	const unsigned int key_len,
	const void *iv,
	const unsigned int iv_len,
	const unsigned int r,
	const unsigned int tag_len
)
{
	assert(desc);
	assert(desc->create);

	assert(key);
	assert(key_len);
	assert(key_len <= kripto_authstream_max_key(desc));
	if(iv_len) assert(iv);
	assert(tag_len <= kripto_authstream_max_tag(desc));

	return desc->create(key, key_len, iv, iv_len, r, tag_len);
}

kripto_authstream *kripto_authstream_recreate
(
	kripto_authstream *s,
	const void *key,
	const unsigned int key_len,
	const void *iv,
	const unsigned int iv_len,
	const unsigned int r,
	const unsigned int tag_len
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->recreate);

	assert(key);
	assert(key_len);
	assert(key_len <= kripto_authstream_max_key(s->desc));
	if(iv_len) assert(iv);
	assert(tag_len <= kripto_authstream_max_tag(s->desc));

	return s->desc->recreate(s, key, key_len, iv, iv_len, r, tag_len);
}

size_t kripto_authstream_encrypt
(
	kripto_authstream *s,
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

size_t kripto_authstream_decrypt
(
	kripto_authstream *s,
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

void kripto_authstream_tag
(
	kripto_authstream *s,
	void *tag,
	const unsigned int len
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->tag);

	s->desc->tag(s, tag, len);
}

void kripto_authstream_destroy(kripto_authstream *s)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->destroy);

	s->desc->destroy(s);
}

unsigned int kripto_authstream_max_key(kripto_authstream_desc *desc)
{
	assert(desc);
	assert(desc->max_key);

	return desc->max_key;
}

unsigned int kripto_authstream_max_iv(kripto_authstream_desc *desc)
{
	assert(desc);

	return desc->max_iv;
}

unsigned int kripto_authstream_max_tag(kripto_authstream_desc *desc)
{
	assert(desc);

	return desc->max_tag;
}
