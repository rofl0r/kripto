#ifndef KRIPTO_MODE_H
#define KRIPTO_MODE_H

typedef const struct kripto_mode *kripto_mode;

#include <kripto/block.h>
#include <kripto/stream.h>

extern kripto_stream kripto_mode_create
(
	kripto_mode mode,
	kripto_block block,
	const void *iv,
	const unsigned int iv_len
);

extern unsigned int kripto_mode_max_iv
(
	kripto_mode mode,
	kripto_block_desc block
);

#endif
