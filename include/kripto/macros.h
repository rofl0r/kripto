/*
 * Copyright (C) 2011 Gregor Pintar <grpintar@gmail.com>
 *
 * Provided that these terms and disclaimer and all copyright notices
 * are retained or reproduced in an accompanying document, permission
 * is granted to deal in this work without restriction, including un-
 * limited rights to use, publicly perform, distribute, sell, modify,
 * merge, give away, or sublicence.
 *
 * This work is provided "AS IS" and WITHOUT WARRANTY of any kind, to
 * the utmost extent permitted by applicable law, neither express nor
 * implied; without malicious intent or gross negligence. In no event
 * may a licensor, author or contributor be held liable for indirect,
 * direct, other damage, loss, or other issues arising in any way out
 * of dealing in the work, even if advised of the possibility of such
 * damage or existence of a defect, except proven that it results out
 * of said person's immediate fault when using the work as intended.
 */

#ifndef KRIPTO_MACROS_H
#define KRIPTO_MACROS_H

#include <stdint.h>

#define U8(x) ((uint8_t *)(x))
#define U16(x) ((uint16_t *)(x))
#define U32(x) ((uint32_t *)(x))
#define U64(x) ((uint64_t *)(x))

#define CU8(x) ((const uint8_t *)(x))
#define CU16(x) ((const uint16_t *)(x))
#define CU32(x) ((const uint32_t *)(x))
#define CU64(x) ((const uint64_t *)(x))

#define S8(x) ((int8_t *)(x))
#define S16(x) ((int16_t *)(x))
#define S32(x) ((int32_t *)(x))
#define S64(x) ((int64_t *)(x))

#define CS8(x) ((const int8_t *)(x))
#define CS16(x) ((const int16_t *)(x))
#define CS32(x) ((const int32_t *)(x))
#define CS64(x) ((const int64_t *)(x))

#define PTR_ADD(x, i) (CU8(x) + (i))
#define PTR_INC(x, i) (x = PTR_ADD((x), (i)))

/* U16 */
#define U8TO16_LE(x)						\
(											\
	((const uint16_t)(CU8(x)[0])) |			\
	((const uint16_t)(CU8(x)[1]) << 8))		\
)

#define U8TO16_BE(x)						\
(											\
	((const uint16_t)(CU8(x)[0]) << 8)) |	\
	((const uint16_t)(CU8(x)[1]))			\
)

#define U16TO8_LE(x, y)						\
{											\
	U8(y)[0] = (const uint8_t)(x);			\
	U8(y)[1] = (const uint8_t)((x) >> 8);	\
}

#define U16TO8_BE(x, y)						\
{											\
	U8(y)[0] = (const uint8_t)((x) >> 8);	\
	U8(y)[1] = (const uint8_t)(x);			\
}

/* U32 */
#define U8TO32_LE(x)						\
(											\
	((const uint32_t)(CU8(x)[0])) |			\
	((const uint32_t)(CU8(x)[1]) << 8) |	\
	((const uint32_t)(CU8(x)[2]) << 16) |	\
	((const uint32_t)(CU8(x)[3]) << 24)		\
)

#define U8TO32_BE(x)						\
(											\
	((const uint32_t)(CU8(x)[0]) << 24) |	\
	((const uint32_t)(CU8(x)[1]) << 16) |	\
	((const uint32_t)(CU8(x)[2]) << 8) |	\
	((const uint32_t)(CU8(x)[3]))			\
)

#define U32TO8_LE(x, y)						\
{											\
	U8(y)[0] = (const uint8_t)(x);			\
	U8(y)[1] = (const uint8_t)((x) >> 8);	\
	U8(y)[2] = (const uint8_t)((x) >> 16);	\
	U8(y)[3] = (const uint8_t)((x) >> 24);	\
}

#define U32TO8_BE(x, y)						\
{											\
	U8(y)[0] = (const uint8_t)((x) >> 24);	\
	U8(y)[1] = (const uint8_t)((x) >> 16);	\
	U8(y)[2] = (const uint8_t)((x) >> 8);	\
	U8(y)[3] = (const uint8_t)(x);			\
}

/* U64 */
#define U8TO64_LE(x)						\
(											\
	((const uint64_t)(CU8(x)[0])) |			\
	((const uint64_t)(CU8(x)[1]) << 8) |	\
	((const uint64_t)(CU8(x)[2]) << 16) |	\
	((const uint64_t)(CU8(x)[3]) << 24) |	\
	((const uint64_t)(CU8(x)[4]) << 32) |	\
	((const uint64_t)(CU8(x)[5]) << 40) |	\
	((const uint64_t)(CU8(x)[6]) << 48) |	\
	((const uint64_t)(CU8(x)[7]) << 56)		\
)

#define U8TO64_BE(x)						\
(											\
	((const uint64_t)(CU8(x)[0]) << 56) |	\
	((const uint64_t)(CU8(x)[1]) << 48) |	\
	((const uint64_t)(CU8(x)[2]) << 40) |	\
	((const uint64_t)(CU8(x)[3]) << 32) |	\
	((const uint64_t)(CU8(x)[4]) << 24) |	\
	((const uint64_t)(CU8(x)[5]) << 16) |	\
	((const uint64_t)(CU8(x)[6]) << 8) |	\
	((const uint64_t)(CU8(x)[7]))			\
)

#define U64TO8_LE(x, y)						\
{											\
	U8(y)[0] = (const uint8_t)(x);			\
	U8(y)[1] = (const uint8_t)((x) >> 8);	\
	U8(y)[2] = (const uint8_t)((x) >> 16);	\
	U8(y)[3] = (const uint8_t)((x) >> 24);	\
	U8(y)[4] = (const uint8_t)((x) >> 32);	\
	U8(y)[5] = (const uint8_t)((x) >> 40);	\
	U8(y)[6] = (const uint8_t)((x) >> 48);	\
	U8(y)[7] = (const uint8_t)((x) >> 56);	\
}

#define U64TO8_BE(x, y)						\
{											\
	U8(y)[0] = (const uint8_t)((x) >> 56);	\
	U8(y)[1] = (const uint8_t)((x) >> 48);	\
	U8(y)[2] = (const uint8_t)((x) >> 40);	\
	U8(y)[3] = (const uint8_t)((x) >> 32);	\
	U8(y)[4] = (const uint8_t)((x) >> 24);	\
	U8(y)[5] = (const uint8_t)((x) >> 16);	\
	U8(y)[6] = (const uint8_t)((x) >> 8);	\
	U8(y)[7] = (const uint8_t)(x);			\
}

/* rotations */
#define ROL(B, X, R) (((X) << (R)) | ((X) >> ((B) - (R))))
#define ROR(B, X, R) (((X) >> (R)) | ((X) << ((B) - (R))))

#define ROL16(X, R) ROL(16, X, R)
#define ROR16(X, R) ROR(16, X, R)

#define ROL32(X, R) ROL(32, X, R)
#define ROR32(X, R) ROR(32, X, R)

#define ROL64(X, R) ROL(64, X, R)
#define ROR64(X, R) ROR(64, X, R)

#endif
