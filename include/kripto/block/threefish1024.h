#ifndef KRIPTO_BLOCK_THREEFISH1024_H
#define KRIPTO_BLOCK_THREEFISH1024_H

#include <kripto/block.h>

extern const kripto_block_desc *const kripto_block_threefish1024;

extern void kripto_block_threefish1024_tweak(kripto_block *s, const void *tweak);

#endif
