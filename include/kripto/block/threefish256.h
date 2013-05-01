#ifndef KRIPTO_BLOCK_THREEFISH256_H
#define KRIPTO_BLOCK_THREEFISH256_H

#include <kripto/block.h>

#ifdef __cplusplus
extern "C"
{
#endif

extern kripto_block_desc *const kripto_block_threefish256;

extern void kripto_block_threefish256_tweak(kripto_block *s, const void *tweak);

#ifdef __cplusplus
}
#endif

#endif
