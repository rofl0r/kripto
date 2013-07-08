#ifndef KRIPTO_STREAM_H
#define KRIPTO_STREAM_H

#include <stddef.h>

typedef struct kripto_stream kripto_stream;
typedef const struct kripto_stream_desc kripto_stream_desc;

extern kripto_stream *kripto_stream_create
(
	kripto_stream_desc *desc,
	const void *key,
	const unsigned int key_len,
	const void *iv,
	const unsigned int iv_len,
	const unsigned int r
);

extern kripto_stream *kripto_stream_change
(
	kripto_stream *s,
	const void *key,
	const unsigned int key_len,
	const void *iv,
	const unsigned int iv_len,
	const unsigned int r
);

extern size_t kripto_stream_encrypt
(
	kripto_stream *s,
	const void *pt,
	void *ct,
	const size_t len
);

extern size_t kripto_stream_decrypt
(
	kripto_stream *s,
	const void *ct,
	void *pt,
	const size_t len
);

extern size_t kripto_stream_prng
(
	kripto_stream *s,
	void *out,
	const size_t len
);

extern void kripto_stream_destroy(kripto_stream *s);

extern unsigned int kripto_stream_max_key(kripto_stream_desc *desc);

extern unsigned int kripto_stream_max_iv(kripto_stream_desc *desc);

#endif
