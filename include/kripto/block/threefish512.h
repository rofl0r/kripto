#ifndef KRIPTO_BLOCK_THREEFISH512_H
#define KRIPTO_BLOCK_THREEFISH512_H

#include <kripto/block.h>

#ifdef __cplusplus
extern "C"
{
#endif

extern kripto_block_desc *const kripto_block_threefish512;

extern void kripto_block_threefish512_tweak(kripto_block *s, const void *tweak);

#ifdef __cplusplus
}
#endif

#endif
