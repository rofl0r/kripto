#ifndef KRIPTO_STREAM_DESC_H
#define KRIPTO_STREAM_DESC_H

#include <stddef.h>

#include <kripto/stream.h>

struct kripto_stream_desc
{
	kripto_stream *(*create)
	(
		const kripto_stream_desc *,
		unsigned int,
		const void *,
		unsigned int,
		const void *,
		unsigned int
	);

	kripto_stream *(*recreate)
	(
		kripto_stream *,
		unsigned int,
		const void *,
		unsigned int,
		const void *,
		unsigned int
	);

	void (*encrypt)
	(
		kripto_stream *,
		const void *,
		void *,
		size_t
	);

	void (*decrypt)
	(
		kripto_stream *,
		const void *,
		void *,
		size_t
	);

	void (*prng)(kripto_stream *, void *, size_t);

	void (*destroy)(kripto_stream *);

	unsigned int maxkey;
	unsigned int maxiv;
};

#endif
