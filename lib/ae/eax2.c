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
#include <string.h>
#include <stdlib.h>

#include <kripto/cast.h>
#include <kripto/memwipe.h>
#include <kripto/stream.h>
#include <kripto/mac.h>
#include <kripto/ae.h>
#include <kripto/desc/ae.h>
#include <kripto/object/ae.h>

#include <kripto/ae/eax2.h>

struct kripto_ae
{
	struct kripto_ae_object obj;
	kripto_stream *stream;
	kripto_mac *mac;
	kripto_mac *header;
	uint8_t *iv;
	unsigned int len;
};

static void eax2_encrypt
(
	kripto_ae *s,
	const void *pt,
	void *ct,
	size_t len
)
{
	kripto_stream_encrypt(s->stream, pt, ct, len);
	kripto_mac_input(s->mac, ct, len);
}

static void eax2_decrypt
(
	kripto_ae *s,
	const void *ct,
	void *pt,
	size_t len
)
{
	kripto_mac_input(s->mac, ct, len);
	kripto_stream_decrypt(s->stream, ct, pt, len);
}

static void eax2_header
(
	kripto_ae *s,
	const void *header,
	size_t len
)
{
	kripto_mac_input(s->header, header, len);
}

static void eax2_tag
(
	kripto_ae *s,
	void *tag,
	unsigned int len
)
{
	unsigned int i;

	kripto_mac_tag(s->mac, tag, len);
	for(i = 0; i < len; i++)
		U8(tag)[i] ^= s->iv[i];

	kripto_mac_tag(s->header, s->iv, len);
	for(i = 0; i < len; i++)
		U8(tag)[i] ^= s->iv[i];
}

static void eax2_destroy(kripto_ae *s)
{
	kripto_stream_destroy(s->stream);
	kripto_mac_destroy(s->mac);
	kripto_mac_destroy(s->header);

	kripto_memwipe(s->iv, s->len);

	free(s);
}

struct ext
{
	kripto_ae_desc desc;
	const kripto_stream_desc *stream;
	const kripto_mac_desc *mac;
};

#define EXT(X) ((const struct ext *)(X))

static kripto_ae *eax2_create
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
	kripto_ae *s;
	uint8_t *buf;
	unsigned int mac_key; /* K1 */
	unsigned int stream_key; /* K2 */

	buf = malloc(tag_len);
	if(!buf) goto err0;

	s = malloc(sizeof(kripto_ae) + tag_len);
	if(!s) goto err1;

	s->obj.desc = desc;
	s->iv = (uint8_t *)s + sizeof(kripto_ae);
	s->len = tag_len;

	/* split key */
	stream_key = (key_len + 1) >> 1;
	if(stream_key > kripto_stream_maxkey(EXT(desc)->stream))
		stream_key = kripto_stream_maxkey(EXT(desc)->stream);
	mac_key = key_len - stream_key;

	/* MAC IV */
	s->mac = kripto_mac_create(EXT(desc)->mac, rounds, key, mac_key, tag_len);
	if(!s->mac) goto err2;
	memset(buf, 0, tag_len);
	kripto_mac_input(s->mac, buf, tag_len);
	kripto_mac_input(s->mac, iv, iv_len);
	kripto_mac_tag(s->mac, s->iv, iv_len);

	/* recreate MAC for encryption/decryption */
	s->mac = kripto_mac_recreate(s->mac, rounds, key, mac_key, tag_len);
	if(!s->mac) goto err3;
	buf[tag_len - 1] = 2;
	kripto_mac_input(s->mac, buf, tag_len);

	/* create stream cipher */
	s->stream = kripto_stream_create
	(
		EXT(desc)->stream, rounds,
		(const uint8_t *)key + mac_key, stream_key,
		s->iv, iv_len
	);
	if(!s->stream) goto err4;

	s->obj.multof = kripto_stream_multof(s->stream);

	/* create MAC for header */
	s->header = kripto_mac_create(EXT(desc)->mac, rounds, key, mac_key, tag_len);
	if(!s->header) goto err5;
	buf[tag_len - 1] = 1;
	kripto_mac_input(s->header, buf, tag_len);

	free(buf);

	return s;

err5: kripto_stream_destroy(s->stream);
err4: kripto_mac_destroy(s->mac);
err3: kripto_memwipe(s->iv, tag_len);
err2: free(s);
err1: free(buf);
err0: return 0;
}

static kripto_ae *eax2_recreate
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
	uint8_t *buf;
	unsigned int mac_key; /* K1 */
	unsigned int stream_key; /* K2 */
	const kripto_ae_desc *desc;

	if(tag_len > s->len)
	{
		desc = s->obj.desc;
		eax2_destroy(s);
		return eax2_create(desc, rounds, key, key_len, iv, iv_len, tag_len);
	}

	if(tag_len < s->len)
		kripto_memwipe(s->iv + tag_len, s->len - tag_len);

	s->len = tag_len;

	buf = malloc(tag_len);
	if(!buf) goto err0;

	/* split key */
	stream_key = (key_len + 1) >> 1;
	if(stream_key > kripto_stream_maxkey(EXT(s->obj.desc)->stream))
		stream_key = kripto_stream_maxkey(EXT(s->obj.desc)->stream);
	mac_key = key_len - stream_key;

	/* MAC IV */
	s->mac = kripto_mac_recreate(s->mac, rounds, key, mac_key, tag_len);
	if(!s->mac) goto err1;
	memset(buf, 0, tag_len);
	kripto_mac_input(s->mac, buf, tag_len);
	kripto_mac_input(s->mac, iv, iv_len);
	kripto_mac_tag(s->mac, s->iv, iv_len);

	/* recreate MAC for encryption/decryption */
	s->mac = kripto_mac_recreate(s->mac, rounds, key, mac_key, tag_len);
	if(!s->mac) goto err1;
	buf[s->len - 1] = 2;
	kripto_mac_input(s->mac, buf, tag_len);

	/* recreate stream cipher */
	s->stream = kripto_stream_recreate
	(
		s->stream, rounds,
		(const uint8_t *)key + mac_key, stream_key,
		s->iv, iv_len
	);
	if(!s->stream) goto err2;

	s->obj.multof = kripto_stream_multof(s->stream);

	/* recreate MAC for header */
	s->header = kripto_mac_recreate(s->header, rounds, key, mac_key, tag_len);
	if(!s->header) goto err3;
	buf[s->len - 1] = 1;
	kripto_mac_input(s->header, buf, tag_len);

	free(buf);

	return s;

err3: kripto_stream_destroy(s->stream);
err2: kripto_mac_destroy(s->mac);
err1: free(buf);
err0:
	kripto_memwipe(s->iv, tag_len);
	free(s);
	return 0;
}

kripto_ae_desc *kripto_ae_eax2
(
	const kripto_stream_desc *stream,
	const kripto_mac_desc *mac
)
{
	struct ext *s;

	s = malloc(sizeof(struct ext));
	if(!s) return 0;

	s->stream = stream;
	s->mac = mac;

	s->desc.create = &eax2_create;
	s->desc.recreate = &eax2_recreate;
	s->desc.encrypt = &eax2_encrypt;
	s->desc.decrypt = &eax2_decrypt;
	s->desc.header = &eax2_header;
	s->desc.tag = &eax2_tag;
	s->desc.destroy = &eax2_destroy;
	s->desc.maxkey = kripto_stream_maxkey(stream) + kripto_mac_maxkey(mac);
	s->desc.maxiv = kripto_stream_maxiv(stream);
	s->desc.maxtag = kripto_mac_maxtag(mac);

	return (kripto_ae_desc *)s;
}
