#ifndef KRIPTO_BLOCK_THREEFISH512_H
#define KRIPTO_BLOCK_THREEFISH512_H

#include <kripto/block.h>

extern const kripto_block_desc *const kripto_block_threefish512;

extern void kripto_block_threefish512_tweak(kripto_block *s, const void *tweak);

#endif
