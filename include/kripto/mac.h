#ifndef KRIPTO_MAC_H
#define KRIPTO_MAC_H

#include <stddef.h>

typedef const struct kripto_mac_desc kripto_mac_desc;
typedef struct kripto_mac kripto_mac;

extern kripto_mac *kripto_mac_create
(
	kripto_mac_desc *desc,
	const void *f,
	const unsigned int r,
	const void *key,
	const unsigned int key_len,
	const unsigned int tag_len
);

extern kripto_mac *kripto_mac_recreate
(
	kripto_mac *s,
	const void *f,
	const unsigned int r,
	const void *key,
	const unsigned int key_len,
	const unsigned int tag_len
);

extern void kripto_mac_input
(
	kripto_mac *s,
	const void *in,
	const size_t len
);

extern void kripto_mac_tag
(
	kripto_mac *s,
	void *tag,
	const unsigned int len
);

extern void kripto_mac_destroy(kripto_mac *s);

extern int kripto_mac_all
(
	kripto_mac_desc *desc,
	const void *f,
	const unsigned int r,
	const void *key,
	const unsigned int key_len,
	const void *in,
	const unsigned int in_len,
	void *tag,
	const unsigned int tag_len
);

extern kripto_mac_desc *kripto_mac_get_desc(const kripto_mac *s);

extern unsigned int kripto_mac_max_tag
(
	kripto_mac_desc *s,
	const void *f
);

#endif
