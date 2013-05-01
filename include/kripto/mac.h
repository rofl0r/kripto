#ifndef KRIPTO_MAC_H
#define KRIPTO_MAC_H

#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef const struct kripto_mac_desc kripto_mac_desc;
typedef struct kripto_mac kripto_mac;

extern kripto_mac *kripto_mac_create
(
	kripto_mac_desc *desc,
	void *f,
	const void *key,
	const unsigned int key_len
);

extern int kripto_mac_init
(
	kripto_mac *s,
	void *f,
	const void *key,
	const unsigned int key_len
);

extern int kripto_mac_update
(
	kripto_mac *s,
	const void *in,
	const size_t len
);

extern int kripto_mac_finish
(
	kripto_mac *s,
	void *out,
	const size_t len
);

extern void kripto_mac_destroy(kripto_mac *s);

extern int kripto_mac_all
(
	kripto_mac_desc *desc,
	void *f,
	const void *key,
	const unsigned int key_len,
	const void *in,
	const unsigned int in_len,
	void *out,
	const unsigned int out_len
);

extern kripto_mac_desc *kripto_mac_get_desc(const kripto_mac *s);

extern unsigned int kripto_mac_max(kripto_mac_desc *s, const void *f);

#ifdef __cplusplus
}
#endif

#endif
