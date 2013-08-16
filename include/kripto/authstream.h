#ifndef KRIPTO_AUTHSTREAM_H
#define KRIPTO_AUTHSTREAM_H

#include <stddef.h>

typedef struct kripto_authstream kripto_authstream;
typedef const struct kripto_authstream_desc kripto_authstream_desc;

extern kripto_authstream *kripto_authstream_create
(
	kripto_authstream_desc *desc,
	const void *key,
	const unsigned int key_len,
	const void *iv,
	const unsigned int iv_len,
	const unsigned int r,
	const unsigned int tag_len
);

extern kripto_authstream *kripto_authstream_recreate
(
	kripto_authstream *s,
	const void *key,
	const unsigned int key_len,
	const void *iv,
	const unsigned int iv_len,
	const unsigned int r,
	const unsigned int tag_len
);

extern size_t kripto_authstream_encrypt
(
	kripto_authstream *s,
	const void *pt,
	void *ct,
	const size_t len
);

extern size_t kripto_authstream_decrypt
(
	kripto_authstream *s,
	const void *ct,
	void *pt,
	const size_t len
);

extern void kripto_authstream_tag
(
	kripto_authstream *s,
	void *tag,
	const unsigned int len
);

extern void kripto_authstream_destroy(kripto_authstream *s);

extern unsigned int kripto_authstream_max_key(kripto_authstream_desc *desc);

extern unsigned int kripto_authstream_max_iv(kripto_authstream_desc *desc);

extern unsigned int kripto_authstream_max_tag(kripto_authstream_desc *desc);

#endif
