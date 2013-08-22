#ifndef KRIPTO_MAC_H
#define KRIPTO_MAC_H

#include <stddef.h>

typedef struct kripto_mac_desc kripto_mac_desc;
typedef struct kripto_mac kripto_mac;

extern kripto_mac *kripto_mac_create
(
	const kripto_mac_desc *desc,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	unsigned int tag_len
);

extern kripto_mac *kripto_mac_recreate
(
	kripto_mac *s,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	unsigned int tag_len
);

extern void kripto_mac_input
(
	kripto_mac *s,
	const void *in,
	size_t len
);

extern void kripto_mac_tag
(
	kripto_mac *s,
	void *tag,
	unsigned int len
);

extern void kripto_mac_destroy(kripto_mac *s);

extern int kripto_mac_all
(
	const kripto_mac_desc *desc,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *in,
	unsigned int in_len,
	void *tag,
	unsigned int tag_len
);

extern const kripto_mac_desc *kripto_mac_getdesc(const kripto_mac *s);

extern unsigned int kripto_mac_maxtag(const kripto_mac_desc *desc);

#endif
