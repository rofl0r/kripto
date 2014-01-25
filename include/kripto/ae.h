#ifndef KRIPTO_AE_H
#define KRIPTO_AE_H

#include <stddef.h>

typedef struct kripto_ae_desc kripto_ae_desc;
typedef struct kripto_ae kripto_ae;

extern kripto_ae *kripto_ae_create
(
	const kripto_ae_desc *desc,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len,
	unsigned int tag_len
);

extern kripto_ae *kripto_ae_recreate
(
	kripto_ae *s,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len,
	unsigned int tag_len
);

extern void kripto_ae_encrypt
(
	kripto_ae *s,
	const void *pt,
	void *ct,
	size_t len
);

extern void kripto_ae_decrypt
(
	kripto_ae *s,
	const void *ct,
	void *pt,
	size_t len
);

extern void kripto_ae_header
(
	kripto_ae *s,
	const void *header,
	size_t len
);

extern void kripto_ae_tag
(
	kripto_ae *s,
	void *tag,
	unsigned int len
);

extern void kripto_ae_destroy(kripto_ae *s);

extern unsigned int kripto_ae_multof(const kripto_ae *s);

extern const kripto_ae_desc *kripto_ae_getdesc(const kripto_ae *s);

extern unsigned int kripto_ae_maxkey(const kripto_ae_desc *desc);

extern unsigned int kripto_ae_maxiv(const kripto_ae_desc *desc);

extern unsigned int kripto_ae_maxtag(const kripto_ae_desc *desc);

#endif
