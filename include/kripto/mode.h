#ifndef KRIPTO_MODE_H
#define KRIPTO_MODE_H

typedef const struct kripto_mode_desc kripto_mode_desc;

#include <kripto/block.h>
#include <kripto/stream.h>

extern kripto_stream *kripto_mode_create
(
	kripto_mode_desc *mode,
	const kripto_block *block,
	const void *iv,
	unsigned int iv_len
);

extern unsigned int kripto_mode_max_iv
(
	kripto_mode_desc *mode,
	kripto_block_desc *block
);

#endif
