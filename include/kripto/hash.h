#ifndef KRIPTO_HASH_H
#define KRIPTO_HASH_H

#include <stddef.h>

typedef const struct kripto_hash_desc kripto_hash_desc;
typedef struct kripto_hash kripto_hash;

extern kripto_hash *kripto_hash_create
(
	kripto_hash_desc *hash,
	size_t len,
	unsigned int r
);

extern kripto_hash *kripto_hash_recreate
(
	kripto_hash *s,
	size_t len,
	unsigned int r
);

extern void kripto_hash_input
(
	kripto_hash *s,
	const void *in,
	size_t len
);

extern void kripto_hash_output
(
	kripto_hash *s,
	void *out,
	size_t len
);

extern void kripto_hash_destroy(kripto_hash *s);

extern int kripto_hash_all
(
	kripto_hash_desc *hash,
	unsigned int r,
	const void *in,
	size_t in_len,
	void *out,
	size_t out_len
);

extern kripto_hash_desc *kripto_hash_get_desc(const kripto_hash *s);

extern size_t kripto_hash_max_output(kripto_hash_desc *s);

extern unsigned int kripto_hash_blocksize(kripto_hash_desc *s);

#endif
