#ifndef KRIPTO_MEMWIPE_H
#define KRIPTO_MEMWIPE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

extern void kripto_memwipe(void *dst, size_t len);

#ifdef __cplusplus
}
#endif

#endif
