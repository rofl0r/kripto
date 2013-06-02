#ifndef KRIPTO_STREAM_DESC_H
#define KRIPTO_STREAM_DESC_H

#include <stddef.h>

#include <kripto/stream.h>

struct kripto_stream_desc
{
	size_t (*encrypt)
	(
		kripto_stream *,
		const void *,
		void *,
		const size_t
	);

	size_t (*decrypt)
	(
		kripto_stream *,
		const void *,
		void *,
		const size_t
	);

	size_t (*prng)(kripto_stream *, void *, const size_t);

	kripto_stream *(*create)
	(
		const void *,
		const unsigned int,
		const void *,
		const unsigned int,
		const unsigned int
	);

	kripto_stream *(*change)
	(
		kripto_stream *,
		const void *,
		const unsigned int,
		const void *,
		const unsigned int,
		const unsigned int
	);

	void (*destroy)(kripto_stream *);

	unsigned int max_key;
	unsigned int max_iv;
	unsigned int max_rounds;
	unsigned int default_rounds;
};

#endif
