#ifndef KRIPTO_CAST_H
#define KRIPTO_CAST_H

#include <stdint.h>

#define U8(X) ((uint8_t *)(X))
#define U16(X) ((uint16_t *)(X))
#define U32(X) ((uint32_t *)(X))
#define U64(X) ((uint64_t *)(X))

#define CU8(X) ((const uint8_t *)(X))
#define CU16(X) ((const uint16_t *)(X))
#define CU32(X) ((const uint32_t *)(X))
#define CU64(X) ((const uint64_t *)(X))

#define VU8(X) ((volatile uint8_t *)(X))
#define VU16(X) ((volatile uint16_t *)(X))
#define VU32(X) ((volatile uint32_t *)(X))
#define VU64(X) ((volatile uint64_t *)(X))

#endif
