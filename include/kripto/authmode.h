#ifndef KRIPTO_AUTHMODE_H
#define KRIPTO_AUTHMODE_H

typedef const struct kripto_authmode_desc kripto_authmode_desc;

#include <kripto/block.h>
#include <kripto/authstream.h>

extern kripto_authstream *kripto_authmode_create
(
	kripto_authmode_desc *authmode,
	const kripto_block *block,
	const void *iv,
	unsigned int iv_len,
	unsigned int tag_len
);

extern unsigned int kripto_authmode_max_iv
(
	kripto_authmode_desc *authmode,
	kripto_block_desc *block
);

extern unsigned int kripto_authmode_max_tag
(
	kripto_authmode_desc *authmode,
	kripto_block_desc *block
);

#endif
