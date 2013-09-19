#ifndef KRIPTO_ROTATE_H
#define KRIPTO_ROTATE_H

#include <stdint.h>

#define ROL(B, X, R) (((X) << (R)) | ((X) >> ((B) - (R))))
#define ROR(B, X, R) (((X) >> (R)) | ((X) << ((B) - (R))))

#define ROL8(X, R) (uint8_t)ROL(8, (const uint8_t)(X), R)
#define ROR8(X, R) (uint8_t)ROR(8, (const uint8_t)(X), R)

#define ROL16(X, R) (uint16_t)ROL(16, (const uint16_t)(X), R)
#define ROR16(X, R) (uint16_t)ROR(16, (const uint16_t)(X), R)

#define ROL32(X, R) (uint32_t)ROL(32, (const uint32_t)(X), R)
#define ROR32(X, R) (uint32_t)ROR(32, (const uint32_t)(X), R)

#define ROL64(X, R) (uint64_t)ROL(64, (const uint64_t)(X), R)
#define ROR64(X, R) (uint64_t)ROR(64, (const uint64_t)(X), R)

#endif
