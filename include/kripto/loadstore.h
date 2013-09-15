/*
 * Copyright (C) 2013 Gregor Pintar <grpintar@gmail.com>
 *
 * Permission is granted to deal in this work without any restriction,
 * including unlimited rights to use, publicly perform, publish,
 * reproduce, relicence, modify, merge, and/or distribute in any form,
 * for any purpose, with or without fee, and by any means.
 *
 * This work is provided "AS IS" and WITHOUT WARRANTY of any kind,
 * to the utmost extent permitted by applicable law. In no event
 * shall a licensor, author or contributor be held liable for any
 * issues arising in any way out of dealing in the work.
 */

#ifndef KRIPTO_LOADSTORE_H
#define KRIPTO_LOADSTORE_H

#include <stdint.h>

#include <kripto/cast.h>

static inline uint16_t LOAD16L(const void *src)
{
	return (uint16_t)CU8(src)[0]
		| ((uint16_t)CU8(src)[1] << 8);
}

static inline uint16_t LOAD16B(const void *src)
{
	return (uint16_t)CU8(src)[1]
		| ((uint16_t)CU8(src)[0] << 8);
}

static inline void STORE16L(const uint16_t src, void *dst)
{
	U8(dst)[0] = (const uint8_t)(src);
	U8(dst)[1] = (const uint8_t)(src >> 8);
}

static inline void STORE16B(const uint16_t src, void *dst)
{
	U8(dst)[1] = (const uint8_t)(src);
	U8(dst)[0] = (const uint8_t)(src >> 8);
}

static inline uint32_t LOAD32L(const void *src)
{
	return (uint32_t)CU8(src)[0]
		| ((uint32_t)CU8(src)[1] << 8)
		| ((uint32_t)CU8(src)[2] << 16)
		| ((uint32_t)CU8(src)[3] << 24);
}

static inline uint32_t LOAD32B(const void *src)
{
	return (uint32_t)CU8(src)[3]
		| ((uint32_t)CU8(src)[2] << 8)
		| ((uint32_t)CU8(src)[1] << 16)
		| ((uint32_t)CU8(src)[0] << 24);
}

static inline void STORE32L(const uint32_t src, void *dst)
{
	U8(dst)[0] = (const uint8_t)(src);
	U8(dst)[1] = (const uint8_t)(src >> 8);
	U8(dst)[2] = (const uint8_t)(src >> 16);
	U8(dst)[3] = (const uint8_t)(src >> 24);
}

static inline void STORE32B(const uint32_t src, void *dst)
{
	U8(dst)[3] = (const uint8_t)(src);
	U8(dst)[2] = (const uint8_t)(src >> 8);
	U8(dst)[1] = (const uint8_t)(src >> 16);
	U8(dst)[0] = (const uint8_t)(src >> 24);
}

static inline uint64_t LOAD64L(const void *src)
{
	return (uint64_t)CU8(src)[0]
		| ((uint64_t)CU8(src)[1] << 8)
		| ((uint64_t)CU8(src)[2] << 16)
		| ((uint64_t)CU8(src)[3] << 24)
		| ((uint64_t)CU8(src)[4] << 32)
		| ((uint64_t)CU8(src)[5] << 40)
		| ((uint64_t)CU8(src)[6] << 48)
		| ((uint64_t)CU8(src)[7] << 56);
}

static inline uint64_t LOAD64B(const void *src)
{
	return (uint64_t)CU8(src)[7]
		| ((uint64_t)CU8(src)[6] << 8)
		| ((uint64_t)CU8(src)[5] << 16)
		| ((uint64_t)CU8(src)[4] << 24)
		| ((uint64_t)CU8(src)[3] << 32)
		| ((uint64_t)CU8(src)[2] << 40)
		| ((uint64_t)CU8(src)[1] << 48)
		| ((uint64_t)CU8(src)[0] << 56);
}

static inline void STORE64L(const uint64_t src, void *dst)
{
	U8(dst)[0] = (const uint8_t)(src);
	U8(dst)[1] = (const uint8_t)(src >> 8);
	U8(dst)[2] = (const uint8_t)(src >> 16);
	U8(dst)[3] = (const uint8_t)(src >> 24);
	U8(dst)[4] = (const uint8_t)(src >> 32);
	U8(dst)[5] = (const uint8_t)(src >> 40);
	U8(dst)[6] = (const uint8_t)(src >> 48);
	U8(dst)[7] = (const uint8_t)(src >> 56);
}

static inline void STORE64B(const uint64_t src, void *dst)
{
	U8(dst)[7] = (const uint8_t)(src);
	U8(dst)[6] = (const uint8_t)(src >> 8);
	U8(dst)[5] = (const uint8_t)(src >> 16);
	U8(dst)[4] = (const uint8_t)(src >> 24);
	U8(dst)[3] = (const uint8_t)(src >> 32);
	U8(dst)[2] = (const uint8_t)(src >> 40);
	U8(dst)[1] = (const uint8_t)(src >> 48);
	U8(dst)[0] = (const uint8_t)(src >> 56);
}

#endif
