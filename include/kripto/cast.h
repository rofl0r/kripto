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

#define S8(X) ((int8_t *)(X))
#define S16(X) ((int16_t *)(X))
#define S32(X) ((int32_t *)(X))
#define S64(X) ((int64_t *)(X))

#define CS8(X) ((const int8_t *)(X))
#define CS16(X) ((const int16_t *)(X))
#define CS32(X) ((const int32_t *)(X))
#define CS64(X) ((const int64_t *)(X))

#define VS8(X) ((volatile int8_t *)(X))
#define VS16(X) ((volatile int16_t *)(X))
#define VS32(X) ((volatile int32_t *)(X))
#define VS64(X) ((volatile int64_t *)(X))

#endif
