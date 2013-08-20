#ifndef KRIPTO_HASH_H
#define KRIPTO_HASH_H

#include <stddef.h>

typedef struct kripto_hash_desc kripto_hash_desc;
typedef struct kripto_hash kripto_hash;

extern kripto_hash *kripto_hash_create
(
	const kripto_hash_desc *desc,
	unsigned int rounds,
	size_t len
);

extern kripto_hash *kripto_hash_recreate
(
	kripto_hash *s,
	unsigned int rounds,
	size_t len
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
	kripto_hash_desc *desc,
	unsigned int rounds,
	const void *in,
	size_t in_len,
	void *out,
	size_t out_len
);

extern const kripto_hash_desc *kripto_hash_getdesc(const kripto_hash *s);

extern size_t kripto_hash_maxout(const kripto_hash_desc *s);

extern unsigned int kripto_hash_blocksize(const kripto_hash_desc *s);

#endif
