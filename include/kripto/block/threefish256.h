#ifndef KRIPTO_BLOCK_THREEFISH256_H
#define KRIPTO_BLOCK_THREEFISH256_H

#include <kripto/block.h>

extern const kripto_block_desc *const kripto_block_threefish256;

extern void kripto_block_threefish256_tweak(kripto_block *s, const void *tweak);

#endif
