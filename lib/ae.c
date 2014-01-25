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

#include <assert.h>
#include <stdint.h>

#include <kripto/desc/ae.h>

#include <kripto/ae.h>

struct kripto_ae
{
	const kripto_ae_desc *desc;
	unsigned int multof;
};

kripto_ae *kripto_ae_create
(
	const kripto_ae_desc *desc,
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
	assert(key_len <= kripto_ae_maxkey(desc));
	assert(iv_len <= kripto_ae_maxiv(desc));
	if(iv_len) assert(iv);
	assert(tag_len <= kripto_ae_maxtag(desc));

	return desc->create(desc, rounds, key, key_len, iv, iv_len, tag_len);
}

kripto_ae *kripto_ae_recreate
(
	kripto_ae *s,
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
	assert(key_len <= kripto_ae_maxkey(s->desc));
	assert(iv_len <= kripto_ae_maxiv(s->desc));
	if(iv_len) assert(iv);
	assert(tag_len <= kripto_ae_maxtag(s->desc));

	return s->desc->recreate(s, rounds, key, key_len, iv, iv_len, tag_len);
}

void kripto_ae_encrypt
(
	kripto_ae *s,
	const void *pt,
	void *ct,
	size_t len
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->encrypt);
	assert(len % kripto_ae_multof(s) == 0);

	s->desc->encrypt(s, pt, ct, len);
}

void kripto_ae_decrypt
(
	kripto_ae *s,
	const void *ct,
	void *pt,
	size_t len
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->decrypt);
	assert(len % kripto_ae_multof(s) == 0);

	s->desc->decrypt(s, ct, pt, len);
}

void kripto_ae_header
(
	kripto_ae *s,
	const void *header,
	size_t len
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->header);

	s->desc->header(s, header, len);
}

void kripto_ae_tag
(
	kripto_ae *s,
	void *tag,
	unsigned int len
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->tag);

	s->desc->tag(s, tag, len);
}

void kripto_ae_destroy(kripto_ae *s)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->destroy);

	s->desc->destroy(s);
}

unsigned int kripto_ae_multof(const kripto_ae *s)
{
	assert(s);
	assert(s->multof);

	return s->multof;
}

const kripto_ae_desc *kripto_ae_getdesc(const kripto_ae *s)
{
	assert(s);
	assert(s->desc);

	return s->desc;
}

unsigned int kripto_ae_maxkey(const kripto_ae_desc *desc)
{
	assert(desc);
	assert(desc->maxkey);

	return desc->maxkey;
}

unsigned int kripto_ae_maxiv(const kripto_ae_desc *desc)
{
	assert(desc);

	return desc->maxiv;
}

unsigned int kripto_ae_maxtag(const kripto_ae_desc *desc)
{
	assert(desc);

	return desc->maxtag;
}
