#ifndef KRIPTO_HASH_DESC_H
#define KRIPTO_HASH_DESC_H

#include <kripto/hash.h>

struct kripto_hash_desc
{
	kripto_hash *(*create)(unsigned int, size_t);

	kripto_hash *(*recreate)(kripto_hash *, unsigned int, size_t);

	void (*input)(kripto_hash *, const void *, size_t);

	void (*output)(kripto_hash *, void *, size_t);

	void (*destroy)(kripto_hash *);

	int (*hash_all)
	(
		const unsigned int,
		const void *,
		size_t,
		void *,
		size_t
	);

	size_t maxout;
	unsigned int blocksize;
};

#endif
