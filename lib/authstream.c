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

#include <kripto/desc/authstream.h>

#include <kripto/authstream.h>

struct kripto_authstream
{
	const kripto_authstream_desc *desc;
};

kripto_authstream *kripto_authstream_create
(
	const kripto_authstream_desc *desc,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len,
	unsigned int tag_len
)
{
	assert(desc);
	assert(desc->create);

	assert(key);
	assert(key_len);
	assert(key_len <= kripto_authstream_maxkey(desc));
	assert(iv_len <= kripto_authstream_maxiv(desc));
	if(iv_len) assert(iv);
	assert(tag_len <= kripto_authstream_maxtag(desc));

	return desc->create(desc, rounds, key, key_len, iv, iv_len, tag_len);
}

kripto_authstream *kripto_authstream_recreate
(
	kripto_authstream *s,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len,
	unsigned int tag_len
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->recreate);

	assert(key);
	assert(key_len);
	assert(key_len <= kripto_authstream_maxkey(s->desc));
	assert(iv_len <= kripto_authstream_maxiv(s->desc));
	if(iv_len) assert(iv);
	assert(tag_len <= kripto_authstream_maxtag(s->desc));

	return s->desc->recreate(s, rounds, key, key_len, iv, iv_len, tag_len);
}

void kripto_authstream_encrypt
(
	kripto_authstream *s,
	const void *pt,
	void *ct,
	size_t len
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->encrypt);
	assert(len % kripto_authstream_multof(s->desc) == 0);

	s->desc->encrypt(s, pt, ct, len);
}

void kripto_authstream_decrypt
(
	kripto_authstream *s,
	const void *ct,
	void *pt,
	size_t len
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->decrypt);
	assert(len % kripto_authstream_multof(s->desc) == 0);

	s->desc->decrypt(s, ct, pt, len);
}

void kripto_authstream_header
(
	kripto_authstream *s,
	const void *header,
	size_t len
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->header);

	s->desc->header(s, header, len);
}

void kripto_authstream_tag
(
	kripto_authstream *s,
	void *tag,
	unsigned int len
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

const kripto_authstream_desc *kripto_authstream_getdesc(const kripto_authstream *s)
{
	assert(s);
	assert(s->desc);

	return s->desc;
}

unsigned int kripto_authstream_multof(const kripto_authstream_desc *desc)
{
	assert(desc);
	assert(desc->multof);

	return desc->multof;
}

unsigned int kripto_authstream_maxkey(const kripto_authstream_desc *desc)
{
	assert(desc);
	assert(desc->maxkey);

	return desc->maxkey;
}

unsigned int kripto_authstream_maxiv(const kripto_authstream_desc *desc)
{
	assert(desc);

	return desc->maxiv;
}

unsigned int kripto_authstream_maxtag(const kripto_authstream_desc *desc)
{
	assert(desc);

	return desc->maxtag;
}
