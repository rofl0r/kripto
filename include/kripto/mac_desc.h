#ifndef KRIPTO_MAC_DESC_H
#define KRIPTO_MAC_DESC_H

#include <kripto/mac.h>

struct kripto_mac_desc
{
	kripto_mac *(*create)
	(
		const void *,
		const unsigned int,
		const void *,
		const unsigned int,
		const unsigned int
	);

	kripto_mac *(*recreate)
	(
		kripto_mac *,
		const void *,
		const unsigned int,
		const void *,
		const unsigned int,
		const unsigned int
	);

	void (*input)(kripto_mac *, const void *, const size_t);
	void (*tag)(kripto_mac *, void *, const size_t);
	void (*destroy)(kripto_mac *);
	unsigned int (*max_output)(const void *);
};

#endif
