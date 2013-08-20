#ifndef KRIPTO_AUTHSTREAM_H
#define KRIPTO_AUTHSTREAM_H

#include <stddef.h>

typedef struct kripto_authstream_desc kripto_authstream_desc;
typedef struct kripto_authstream kripto_authstream;

extern kripto_authstream *kripto_authstream_create
(
	const kripto_authstream_desc *desc,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len,
	unsigned int tag_len
);

extern kripto_authstream *kripto_authstream_recreate
(
	kripto_authstream *s,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len,
	unsigned int tag_len
);

extern size_t kripto_authstream_encrypt
(
	kripto_authstream *s,
	const void *pt,
	void *ct,
	size_t len
);

extern size_t kripto_authstream_decrypt
(
	kripto_authstream *s,
	const void *ct,
	void *pt,
	size_t len
);

extern void kripto_authstream_tag
(
	kripto_authstream *s,
	void *tag,
	unsigned int len
);

extern void kripto_authstream_destroy(kripto_authstream *s);

extern const kripto_authstream_desc *kripto_authstream_getdesc(const kripto_authstream *s);

extern unsigned int kripto_authstream_maxkey(const kripto_authstream_desc *desc);

extern unsigned int kripto_authstream_maxiv(const kripto_authstream_desc *desc);

extern unsigned int kripto_authstream_maxtag(const kripto_authstream_desc *desc);

#endif
