#ifndef KRIPTO_BLOCK_H
#define KRIPTO_BLOCK_H

#ifdef __cplusplus
extern "C"
{
#endif

typedef const struct kripto_block_desc *kripto_block_desc;
typedef struct kripto_block *kripto_block;

extern kripto_block kripto_block_create
(
	kripto_block_desc desc,
	const void *key,
	const unsigned int key_len,
	const unsigned int r
);

extern void kripto_block_encrypt
(
	const kripto_block s,
	const void *pt,
	void *ct
);

extern void kripto_block_decrypt
(
	const kripto_block s,
	const void *ct,
	void *pt
);

extern void kripto_block_destroy(kripto_block s);

extern kripto_block_desc kripto_block_get_desc(const kripto_block s);

extern unsigned int kripto_block_size(kripto_block_desc desc);

extern unsigned int kripto_block_max_key(kripto_block_desc desc);

extern unsigned int kripto_block_max_rounds(kripto_block_desc desc);

extern unsigned int kripto_block_default_rounds(kripto_block_desc desc);

#ifdef __cplusplus
}
#endif

#endif
