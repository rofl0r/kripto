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

#include <kripto/mac.h>
#include <kripto/desc/mac.h>

struct kripto_mac
{
	const kripto_mac_desc *desc;
};

kripto_mac *kripto_mac_create
(
	const kripto_mac_desc *desc,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	unsigned int tag_len
)
{
	assert(desc);
	assert(desc->create);

	assert(key);
	assert(key_len);

	return desc->create(desc, rounds, key, key_len, tag_len);
}

kripto_mac *kripto_mac_recreate
(
	kripto_mac *s,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	unsigned int tag_len
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->recreate);

	assert(key);
	assert(key_len);

	return s->desc->recreate(s, rounds, key, key_len, tag_len);
}

void kripto_mac_input(kripto_mac *s, const void *in, size_t len)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->input);

	s->desc->input(s, in, len);
}

void kripto_mac_tag(kripto_mac *s, void *tag, unsigned int len)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->tag);

	s->desc->tag(s, tag, len);
}

void kripto_mac_destroy(kripto_mac *s)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->destroy);

	s->desc->destroy(s);
}

int kripto_mac_all
(
	const kripto_mac_desc *desc,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *in,
	unsigned int in_len,
	void *tag,
	unsigned int tag_len
)
{
	kripto_mac *s;

	assert(desc);

	s = kripto_mac_create(desc, rounds, key, key_len, tag_len);
	if(!s) return -1;

	kripto_mac_input(s, in, in_len);
	kripto_mac_tag(s, tag, tag_len);

	kripto_mac_destroy(s);

	return 0;
}

const kripto_mac_desc *kripto_mac_getdesc(const kripto_mac *s)
{
	assert(s);
	assert(s->desc);

	return s->desc;
}

unsigned int kripto_mac_maxtag(const kripto_mac_desc *desc)
{
	assert(desc);

	return desc->maxtag;
}

unsigned int kripto_mac_maxkey(const kripto_mac_desc *desc)
{
	assert(desc);

	return desc->maxkey;
}
