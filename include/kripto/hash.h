#ifndef KRIPTO_HASH_H
#define KRIPTO_HASH_H

#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef const struct kripto_hash_desc kripto_hash_desc;
typedef struct kripto_hash kripto_hash;

extern kripto_hash *kripto_hash_create
(
	kripto_hash_desc *hash,
	const size_t len,
	const unsigned int r
);

extern void kripto_hash_init(kripto_hash *s, const size_t len);

extern int kripto_hash_input
(
	kripto_hash *s,
	const void *in,
	const size_t len
);

extern void kripto_hash_finish(kripto_hash *s);

extern int kripto_hash_output
(
	kripto_hash *s,
	void *out,
	const size_t len
);

extern void kripto_hash_destroy(kripto_hash *s);

extern int kripto_hash_all
(
	kripto_hash_desc *hash,
	const unsigned int r,
	const void *in,
	const size_t in_len,
	void *out,
	const size_t out_len
);

extern kripto_hash_desc *kripto_hash_get_desc(const kripto_hash *s);

extern unsigned int kripto_hash_max(kripto_hash_desc *s);

extern unsigned int kripto_hash_blocksize(kripto_hash_desc *s);

#ifdef __cplusplus
}
#endif

#endif
